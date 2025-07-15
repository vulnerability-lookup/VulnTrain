import argparse
import json
from typing import Any, Generator

import valkey
from datasets import Dataset, DatasetDict

import requests
import os
import time

from vulntrain.config import valkey_host, valkey_port
from vulntrain.utils import (
    strip_markdown,
    extract_cpe,
    extract_cpe_csaf,
    extract_cvss_cve,
    extract_cvss_from_github_advisory,
    extract_cvss_from_pysec,
    extract_cvss_from_csaf,
)

class VulnExtractor:
    def __init__(self, sources: list[str], nb_rows: int):
        self.sources = sources
        self.nb_rows = nb_rows
        self.valkey_client = valkey.Valkey(
            host=valkey_host, port=valkey_port, decode_responses=True
        )

    def get_vulnerability_meta(self, vulnerability_id: str) -> dict[str, Any]:
        _vid = vulnerability_id.lower()
        metadata = {}

        for meta_name, meta_uuid in self.valkey_client.hgetall(f"{_vid}:meta").items():
            key = f"{meta_name}:{meta_uuid}"
            if self.valkey_client.exists(key):
                meta_type = self.valkey_client.type(key)
                if meta_type == "string":
                    metadata[meta_name] = self.valkey_client.get(key)
                elif meta_type == "hash":
                    metadata[meta_name] = self.valkey_client.hgetall(key)
            else:
                print(f"Warning: Unable to find meta {meta_uuid} for {meta_name}")

        return metadata

    def get_vulnerability(
        self, vulnerability_id: str, with_meta: bool = False
    ) -> dict[str, Any] | None:
        _vid = vulnerability_id.lower()
        _vuln = self.valkey_client.get(_vid) 
        if not _vuln:
            return None

        vuln = json.loads(_vuln)
        if with_meta:
            vuln["vulnerability-lookup:meta"] = self.get_vulnerability_meta(_vid)

        return vuln

    def get_all( self, source: str, with_meta: bool = False ) -> Generator[dict[str, Any], None, None]:
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
                    if with_meta and 'id' in vuln:
                        vid = vuln['id']
                        meta = self.get_vulnerability_meta(vid)
                        vuln["vulnerability-lookup:meta"] = meta
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

    def extract_cve(self, vuln: dict[str, Any]) -> dict[str, Any]:
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

        cwe_id = ""
        cwe_desc = ""
        problem_types = vuln["containers"]["cna"].get("problemTypes", [])
        if problem_types:
            descriptions = problem_types[0].get("descriptions", [])
            if descriptions:
                cwe_id = descriptions[0].get("cweId", "")
                cwe_desc = descriptions[0].get("description", "")

        if not vuln_description:
            return {}

        return {
            "id": vuln_id,
            "title": vuln_title,
            "description": vuln_description,
            "references": patch_references,
            "cwe_id": cwe_id,
            "cwe_description": cwe_desc,
        }



    def extract_ghsa(self, vuln: dict[str, Any]) -> dict[str, Any]:
        cvss_scores = extract_cvss_from_github_advisory(vuln)
        references = vuln.get("references", [])

        patch_references = [
            ref.get("url", "")
            for ref in references
            if "type" in ref and "patch" in ref["type"].lower()
            and self.is_url_alive(ref.get("url", ""))
        ]

        cwes = vuln.get("database_specific", {}).get("cwe_ids", [])

        return {
            "id": vuln.get("id", ""),
            "title": strip_markdown(vuln.get("summary", "")),
            "cwes": cwes,
            "patch_links": patch_references,
        }


    def extract_pysec(self, vuln: dict[str, Any]) -> dict[str, Any]:
        cvss_scores = extract_cvss_from_pysec(vuln)
        references = vuln.get("references", [])

        patch_references = [
            ref.get("url", "")
            for ref in references
            if "type" in ref and "patch" in ref["type"].lower()
            and self.is_url_alive(ref.get("url", ""))
        ]

        return {
            "id": vuln["id"],
            "patch_links": patch_references,
        }


    def extract_csaf(self, vuln: dict[str, Any]) -> dict[str, Any]:
        cvss_scores = extract_cvss_from_csaf(vuln)

        # ➤ Extract description (optional, commented)
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

        # ➤ Extract patch URLs
        references = vuln.get("document", {}).get("references", [])
        raw_patch_links = [
            ref.get("url", "")
            for ref in references
            if "category" in ref and "patch" in ref["category"].lower()
        ]
        patch_references = self.filter_alive_links(raw_patch_links)

        # ➤ Extract CWEs
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
            # "description": description,
            "patch_links": patch_references,
            "cwes": cwes,
            # "cpes": extract_cpe_csaf(vuln),
            # "cvss_v4_0": cvss_scores.get("cvss_v4_0", None),
            # "cvss_v3_1": cvss_scores.get("cvss_v3_1", None),
            # "cvss_v3_0": cvss_scores.get("cvss_v3_0", None),
            # "cvss_v2_0": cvss_scores.get("cvss_v2_0", None),
        }


    def __call__(self) -> Generator[dict[str, Any], None, None]:
        count = 0
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

            for vuln in self.get_all(source, True):
                vuln_data = extractor(vuln)

                if not vuln_data.get("description"):
                    continue

                yield vuln_data

                count += 1
                if count == self.nb_rows:
                    return
             
    
def main():
    parser = argparse.ArgumentParser(description="Dataset generation.")
    parser.add_argument(
        "--sources",
        required=True,
        help="Comma-separated list of sources (cvelistv5, github, pysec)",
    )
    parser.add_argument(
        "--nb-rows", type=int, default=0, help="Number of rows in the dataset"
    )

    args = parser.parse_args()

    sources = args.sources.split(",")
    extractor = VulnExtractor(sources, args.nb_rows)
    vulns = list(extractor())

    dataset = Dataset.from_list(vulns)
    dataset_dict = dataset.train_test_split(test_size=0.1)

    dataset_dict = DatasetDict(
        {"train": dataset_dict["train"], "test": dataset_dict["test"]}
    )
    print(dataset_dict)


if __name__ == "__main__":
    main()
