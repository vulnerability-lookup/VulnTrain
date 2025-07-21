import argparse
import json
import logging
import time
from datetime import datetime
from typing import Any, Generator

import requests
from datasets import Dataset, DatasetDict

from vulntrain.config import GITHUB_TOKEN
from vulntrain.utils import (
    extract_cvss_from_csaf,
    extract_cvss_from_github_advisory,
    extract_cvss_from_pysec,
    strip_markdown,
)

# Set up the logger only once
logger = logging.getLogger("custom_logger")
logger.setLevel(logging.DEBUG)  # Capture all levels

if not logger.handlers:
    # File handler
    file_handler = logging.FileHandler("cwe-dataset.log")
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

def log_message(level: str, message: str, display: bool = False):
    """Log a message to file (and optionally to console) with a given level."""
    level = level.lower()
    log_func = {
        "debug": logger.debug,
        "info": logger.info,
        "warning": logger.warning,
        "error": logger.error,
        "critical": logger.critical
    }.get(level)

    if log_func is None:
        raise ValueError(f"Invalid log level: {level}")

    log_func(message)

    if display:
        print(f"{datetime.now().isoformat()} - {level.upper()} - {message}")


HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}"
}


class VulnExtractor:
    def __init__(self, sources: list[str], nb_rows: int, max_retries: int = 3):
        self.sources = sources
        self.nb_rows = nb_rows
        self.max_retries = max_retries

    def get_all(self, source: str, with_meta: bool = False) -> Generator[dict[str, Any], None, None]:
        page = 1
        per_page = 1000

        while True:
            url = f"https://vulnerability.circl.lu/api/vulnerability/last/{source}/{per_page}?page={page}"
            retries = 0

            while retries < self.max_retries:
                try:
                    response = requests.get(url, headers={"accept": "application/json"}, timeout=10)
                    response.raise_for_status()
                    data = response.json()

                    if not data:
                        return  # Stop if empty page

                    for vuln in data:
                        yield vuln

                    page += 1
                    break  # Exit retry loop

                except requests.exceptions.Timeout:
                    retries += 1
                    wait = 2 ** retries
                    print(f"[Timeout] Retrying page {page} from '{source}' in {wait}s (attempt {retries}/{self.max_retries})")
                    time.sleep(wait)

                except requests.exceptions.RequestException as e:
                    print(f"[Error] Failed to fetch page {page} from '{source}': {e}")
                    return  # Do not retry on other errors


    def is_url_alive(self, url: str, timeout: int = 5) -> bool:
        try:
            response = requests.head(url, timeout=timeout, allow_redirects=True)
            if response.status_code != 200:
                log_message("error", f"[{url}] - is_url_alive - {response.reason}", display=False)
            return response.status_code == 200
        except requests.RequestException:
            return False


    def filter_alive_links(self, urls: list[str]) -> list[str]:
        return [url for url in urls if self.is_url_alive(url)]


    def fetch_patch_and_message(self, url: str) -> dict[str, str] | None:
        if "github.com" in url and "/commit/" in url and self.is_url_alive(url):
            return self._fetch_github_patch(url)
        elif "gitlab.com" in url and "/-/commit/" in url and self.is_url_alive(url):
            return self._fetch_gitlab_patch(url)
        # elif "bitbucket.org" in url and "/commits/" in url:
        #     return self._fetch_bitbucket_patch(url)
        else:
            return None  # Unknown or unsupported platform


    def _fetch_github_patch(self, url: str) -> dict[str, str] | None:
        patch_url = url if url.endswith(".patch") else url + ".patch"
        try:
            response = requests.get(patch_url, headers=HEADERS, timeout=10)
            if response.status_code != 200:
                log_message("error", f"[{patch_url}] - _fetch_github_patch - {response.reason}", display=False)
            response.raise_for_status()
            patch_text = response.text.strip()

            lines = patch_text.splitlines()
            commit_msg_lines = []
            for line in lines:
                if line.startswith("Subject:"):
                    commit_msg_lines.append(line.split("Subject:")[1].strip())
                elif commit_msg_lines and line.strip() == "":
                    break
                elif commit_msg_lines:
                    commit_msg_lines.append(line.strip())

            commit_message = " ".join(commit_msg_lines)
            return {
                "url": url,
                "platform": "github",
                "patch_text": patch_text,
                "commit_message": commit_message
            }
        except Exception as e:
            log_message("error", f"[{patch_url}] - _fetch_github_patch - {e}", display=False)
            return None


    def _fetch_gitlab_patch(self, url: str) -> dict[str, str] | None:
        patch_url = url if url.endswith(".patch") else url + ".patch"
        try:
            response = requests.get(patch_url, timeout=10)
            if response.status_code != 200:
                log_message("error", f"[{patch_url}] - _fetch_gitlab_patch - {response.reason}", display=False)
            response.raise_for_status()
            patch_text = response.text.strip()

            lines = patch_text.splitlines()
            subject_lines = [line for line in lines if line.startswith("Subject:")]
            commit_message = subject_lines[0].replace("Subject:", "").strip() if subject_lines else ""

            return {
                "url": url,
                "platform": "gitlab",
                "patch_text": patch_text,
                "commit_message": commit_message
            }
        except Exception as e:
            print(f"GitLab patch fetch failed for {url}: {e}")
            return None
        

    def extract_cve(self, vuln: dict[str, Any]) -> dict[str, Any]:
        try:
            vuln_id = vuln["cveMetadata"]["cveId"]
            vuln_title = vuln["containers"]["cna"].get("title", "")
            vuln_description = next(
                (
                    desc["value"]
                    for desc in vuln["containers"]["cna"].get("descriptions", [])
                    if desc["lang"].startswith("en")
                ),
                "",
            )

            # Collect patch reference URLs
            patch_references = [
                ref.get("url", "")
                for ref in vuln["containers"]["cna"].get("references", [])
                if "tags" in ref and "patch" in ref["tags"]
            ]

            patches = []
            for url in patch_references:
                patch_info = self.fetch_patch_and_message(url)
                if patch_info:
                    patches.append(patch_info)

            if not patches:
                return {}

            # Extract CWE information
            cwe_id = ""
            cwe_desc = ""
            problem_types = vuln["containers"]["cna"].get("problemTypes", [])
            if problem_types:
                descriptions = problem_types[0].get("descriptions", [])
                if descriptions:
                    cwe_id = descriptions[0].get("cweId", "")
                    cwe_desc = descriptions[0].get("description", "")
            
            ###test###
            # print(f"[EXTRACTED CVE] {vuln_id} → {json.dumps({
            #     'title': vuln_title,
            #     'description': vuln_description[:100],  # Short preview
            #     'patches': [
            #         {
            #             'url': patch['url'],
            #             'platform': patch['platform'],
            #             'commit_message': patch['commit_message'],
            #             'patch_preview': patch['patch_text'][:200]  # First 200 characters
            #         } for patch in patches
            #     ]
            # }, indent=2)}")
            ###test###

            return {
                "id": vuln_id,
                "title": vuln_title,
                "description": vuln_description,
                "references": patch_references,
                "patches": patches,
                "cwe_id": cwe_id,
                "cwe_description": cwe_desc,
            }

        except KeyError:
            return {}


    def extract_ghsa(self, vuln: dict[str, Any]) -> dict[str, Any]:
        references = vuln.get("references", [])

        patch_references = [
            ref.get("url", "")
            for ref in references
            if "type" in ref and "patch" in ref["type"].lower()
        ]
        if not patch_references:
            return {}

        cwes = vuln.get("database_specific", {}).get("cwe_ids", [])

        return {
            "id": vuln.get("id", ""),
            "title": strip_markdown(vuln.get("summary", "")),
            "cwes": cwes,
            "patch_links": patch_references,
        }

    def extract_pysec(self, vuln: dict[str, Any]) -> dict[str, Any]:
        references = vuln.get("references", [])

        patch_references = [
            ref.get("url", "")
            for ref in references
            if "type" in ref and "patch" in ref["type"].lower()
        ]
        if not patch_references:
            return {}

        return {
            "id": vuln["id"],
            "patch_links": patch_references,
        }

    def extract_csaf(self, vuln: dict[str, Any]) -> dict[str, Any]:
        description = " ".join(
            [
                note["text"]
                for vulnerability in vuln.get("vulnerabilities", [])
                for note in vulnerability.get("notes", [])
                if note.get("category") == "summary"
            ]
        )
        if not description:
            description = next(
                (
                    note["text"]
                    for note in vuln.get("document", {}).get("notes", [])
                    if note.get("category") == "summary"
                ),
                "",
            )

        references = vuln.get("document", {}).get("references", [])
        raw_patch_links = [
            ref.get("url", "")
            for ref in references
            if "category" in ref and "patch" in ref["category"].lower()
        ]
        patch_references = self.filter_alive_links(raw_patch_links)
        if not patch_references:
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
            "patch_links": patch_references,
            "cwes": cwes,
        }

    def __call__(self) -> Generator[dict[str, Any], None, None]:
        count = 0
        with open("vulns_success.jsonl", "w") as success_file, open("vulns_error.jsonl", "w") as error_file:
            for source in self.sources:
                match source:
                    case "cvelistv5":
                        extractor = self.extract_cve
                    case "github":
                        extractor = self.extract_ghsa
                    case "pysec":
                        extractor = self.extract_pysec
                    case str() as s if s.startswith("csaf_"):
                        extractor = self.extract_csaf
                    case _:
                        print("No parser for this source.")
                        continue

                for vuln in self.get_all(source, with_meta=False):
                    try:
                        vuln_data = extractor(vuln)

                        if not vuln_data or not vuln_data.get("description"):
                            # error_file.write(json.dumps(vuln) + "\n")
                            continue

                        # success_file.write(json.dumps(vuln_data) + "\n")
                        yield vuln_data

                        count += 1
                        print(f"{count} {vuln_data.get('id')}")
                        if self.nb_rows and count >= self.nb_rows:
                            return
                    except Exception as e:
                        print(f"Error processing vulnerability: {e}")
                        # error_file.write(json.dumps(vuln) + "\n")

def main():
    parser = argparse.ArgumentParser(description="Dataset generation.")
    parser.add_argument(
        "--sources",
        required=True,
        help="Comma-separated list of sources (cvelistv5, github, pysec, csaf_xxx)",
    )
    parser.add_argument(
        "--nb-rows", type=int, default=0, help="Number of rows in the dataset (0 = all)"
    )

    args = parser.parse_args()

    sources = args.sources.split(",")
    extractor = VulnExtractor(sources, args.nb_rows)

    list(extractor())  

if __name__ == "__main__":
    main()
