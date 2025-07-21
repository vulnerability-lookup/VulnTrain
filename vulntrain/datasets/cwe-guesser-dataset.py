import argparse
import json
import logging
from typing import Any, Generator, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from vulntrain.utils import (
    strip_markdown,
    extract_cvss_from_github_advisory,
    extract_cvss_from_pysec,
    extract_cvss_from_csaf,
)

logging.basicConfig(level=logging.INFO)

class VulnExtractor:
    def __init__(self, sources: list[str], nb_rows: int, max_workers: int = 16):
        self.sources = sources
        self.nb_rows = nb_rows
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

    def get_all(self, source: str, with_meta: bool = False) -> Generator[dict[str, Any], None, None]:
        page = 1
        per_page = 1000

        while True:
            url = f"https://vulnerability.circl.lu/api/vulnerability/last/{source}/{per_page}?page={page}"
            try:
                response = requests.get(url, headers={"accept": "application/json"}, timeout=10)
                response.raise_for_status()
                data = response.json()
                if not data:
                    break
                for vuln in data:
                    yield vuln
                page += 1
            except requests.RequestException as e:
                logging.warning(f"Error fetching page {page} from source '{source}': {e}")
                break

    def is_url_alive(self, url: str, timeout: int = 5) -> bool:
        try:
            response = requests.head(url, timeout=timeout, allow_redirects=True)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def filter_alive_links(self, urls: list[str]) -> list[str]:
        futures = {self.executor.submit(self.is_url_alive, url): url for url in urls}
        alive = []
        for future in as_completed(futures):
            url = futures[future]
            try:
                if future.result():
                    alive.append(url)
            except Exception:
                pass
        return alive

    def fetch_patch_and_message(self, url: str) -> Optional[dict[str, str]]:
        if "github.com" in url and "/commit/" in url:
            return self._fetch_patch_generic(url, "github")
        elif "gitlab.com" in url and "/-/commit/" in url:
            return self._fetch_patch_generic(url, "gitlab")
        elif "bitbucket.org" in url and "/commits/" in url:
            return self._fetch_patch_generic(url, "bitbucket")
        return None

    def _fetch_patch_generic(self, url: str, platform: str) -> Optional[dict[str, str]]:
        patch_url = url + ".diff"
        try:
            response = requests.get(patch_url, timeout=10)
            response.raise_for_status()
            patch_text = response.text.strip()
            commit_message = ""  # No commit message in .diff
            return {
                "url": url,
                "platform": platform,
                "patch_text": patch_text,
                "commit_message": commit_message
            }
        except Exception as e:
            logging.warning(f"{platform} patch fetch failed: {url} | {e}")
            return None

    def _parallel_fetch_patches(self, urls: list[str]) -> list[dict[str, str]]:
        futures = {self.executor.submit(self.fetch_patch_and_message, url): url for url in urls}
        results = []
        for future in as_completed(futures):
            try:
                patch = future.result()
                if patch:
                    results.append(patch)
            except Exception:
                continue
        return results

    def extract_cve(self, vuln: dict[str, Any]) -> dict[str, Any]:
        try:
            vuln_id = vuln["cveMetadata"]["cveId"]
            vuln_title = vuln["containers"]["cna"].get("title", "")
            vuln_description = next(
                (desc["value"]
                 for desc in vuln["containers"]["cna"].get("descriptions", [])
                 if desc["lang"].startswith("en")),
                "",
            )

            patch_urls = [
                ref.get("url", "")
                for ref in vuln["containers"]["cna"].get("references", [])
                if "tags" in ref and "patch" in ref["tags"]
            ]
            patch_urls = self.filter_alive_links(patch_urls)
            patches = self._parallel_fetch_patches(patch_urls)

            if not patches:
                return {}

            cwe_id = ""
            cwe_desc = ""
            problem_types = vuln["containers"]["cna"].get("problemTypes", [])
            if problem_types:
                descriptions = problem_types[0].get("descriptions", [])
                if descriptions:
                    cwe_id = descriptions[0].get("cweId", "")
                    cwe_desc = descriptions[0].get("description", "")

            return {
                "id": vuln_id,
                "title": vuln_title,
                "description": vuln_description,
                "references": patch_urls,
                "patches": patches,
                "cwe_id": cwe_id,
                "cwe_description": cwe_desc,
            }
        except Exception as e:
            logging.error(f"extract_cve failed: {e}")
            return {}

    def extract_ghsa(self, vuln: dict[str, Any]) -> dict[str, Any]:
        refs = vuln.get("references", [])
        patch_urls = [
            ref.get("url", "")
            for ref in refs
            if "type" in ref and "patch" in ref["type"].lower()
        ]
        patch_urls = self.filter_alive_links(patch_urls)
        if not patch_urls:
            return {}
        cwes = vuln.get("database_specific", {}).get("cwe_ids", [])
        return {
            "id": vuln.get("id", ""),
            "title": strip_markdown(vuln.get("summary", "")),
            "cwes": cwes,
            "patch_links": patch_urls,
        }

    def extract_pysec(self, vuln: dict[str, Any]) -> dict[str, Any]:
        refs = vuln.get("references", [])
        patch_urls = [
            ref.get("url", "")
            for ref in refs
            if "type" in ref and "patch" in ref["type"].lower()
        ]
        patch_urls = self.filter_alive_links(patch_urls)
        if not patch_urls:
            return {}
        return {
            "id": vuln["id"],
            "patch_links": patch_urls,
        }

    def extract_csaf(self, vuln: dict[str, Any]) -> dict[str, Any]:
        description = " ".join(
            note["text"]
            for vulnerability in vuln.get("vulnerabilities", [])
            for note in vulnerability.get("notes", [])
            if note.get("category") == "summary"
        )
        if not description:
            description = next(
                (note["text"]
                 for note in vuln.get("document", {}).get("notes", [])
                 if note.get("category") == "summary"),
                "",
            )

        references = vuln.get("document", {}).get("references", [])
        patch_urls = [
            ref.get("url", "")
            for ref in references
            if "category" in ref and "patch" in ref["category"].lower()
        ]
        patch_urls = self.filter_alive_links(patch_urls)
        if not patch_urls:
            return {}

        cwes = []
        for v in vuln.get("vulnerabilities", []):
            cwe = v.get("cwe", {})
            if cwe:
                cwes.append({
                    "id": cwe.get("id", ""),
                    "name": cwe.get("name", "")
                })

        return {
            "id": vuln["document"]["tracking"]["id"],
            "title": vuln["document"]["title"],
            "description": description,
            "patch_links": patch_urls,
            "cwes": cwes,
        }

    def __call__(self) -> Generator[dict[str, Any], None, None]:
        count = 0
        with open("vulns_success.jsonl", "w") as success_file, open("vulns_error.jsonl", "w") as error_file:
            for source in self.sources:
                extractor = {
                    "cvelistv5": self.extract_cve,
                    "github": self.extract_ghsa,
                    "pysec": self.extract_pysec,
                }.get(source) or (self.extract_csaf if source.startswith("csaf_") else None)

                if not extractor:
                    logging.warning(f"No parser for source '{source}'")
                    continue

                for vuln in self.get_all(source):
                    try:
                        vuln_data = extractor(vuln)
                        if not vuln_data or not vuln_data.get("description"):
                            error_file.write(json.dumps(vuln) + "\n")
                            continue
                        success_file.write(json.dumps(vuln_data) + "\n")
                        yield vuln_data
                        count += 1
                        if self.nb_rows and count >= self.nb_rows:
                            return
                    except Exception as e:
                        logging.error(f"Error processing vulnerability: {e}")
                        error_file.write(json.dumps(vuln) + "\n")

def main():
    parser = argparse.ArgumentParser(description="Dataset generation.")
    parser.add_argument(
        "--sources", required=True,
        help="Comma-separated list of sources (cvelistv5, github, pysec, csaf_xxx)"
    )
    parser.add_argument(
        "--nb-rows", type=int, default=0,
        help="Number of rows in the dataset (0 = all)"
    )
    args = parser.parse_args()
    sources = args.sources.split(",")
    extractor = VulnExtractor(sources, args.nb_rows)
    list(extractor())

if __name__ == "__main__":
    main()
