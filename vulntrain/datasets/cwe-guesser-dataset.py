import argparse
import json
from typing import Any, Generator

from datasets import Dataset, DatasetDict
import requests

from vulntrain.utils import (
    strip_markdown,
    extract_cvss_from_github_advisory,
    extract_cvss_from_pysec,
    extract_cvss_from_csaf,
)

class VulnExtractor:
    def __init__(self, sources: list[str], nb_rows: int):
        self.sources = sources
        self.nb_rows = nb_rows

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
                    break  # Stop if empty page

                for vuln in data:
                    yield vuln

                page += 1  

            except requests.RequestException as e:
                print(f"Error fetching page {page} from source '{source}': {e}")
                break

    def is_url_alive(self, url: str, timeout: int = 5) -> bool:
        try:
            response = requests.head(url, timeout=timeout, allow_redirects=True)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def filter_alive_links(self, urls: list[str]) -> list[str]:
        return [url for url in urls if self.is_url_alive(url)]

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

            patch_references = [
                ref.get("url", "")
                for ref in vuln["containers"]["cna"].get("references", [])
                if "tags" in ref and "patch" in ref["tags"]
                and self.is_url_alive(ref.get("url", ""))
            ]
            print(f"Found {len(patch_references)} patch references for {vuln_id}")
            if not patch_references or not vuln_description:
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
                "references": patch_references,
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
            and self.is_url_alive(ref.get("url", ""))
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
            and self.is_url_alive(ref.get("url", ""))
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
                            error_file.write(json.dumps(vuln) + "\n")
                            continue

                        success_file.write(json.dumps(vuln_data) + "\n")
                        yield vuln_data

                        count += 1
                        if self.nb_rows and count >= self.nb_rows:
                            return
                    except Exception as e:
                        print(f"Error processing vulnerability: {e}")
                        error_file.write(json.dumps(vuln) + "\n")

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
