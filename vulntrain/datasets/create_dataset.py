import argparse
import json
from typing import Any, Generator

import valkey
from datasets import Dataset, DatasetDict

from vulntrain.config import valkey_host, valkey_port
from vulntrain.utils import (
    extract_cpe,
    extract_cpe_csaf,
    extract_cvss_cve,
    extract_cvss_from_csaf,
    extract_cvss_from_github_advisory,
    extract_cvss_from_pysec,
    strip_markdown,
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

    def get_all(
        self, source: str, with_meta: bool = False
    ) -> Generator[dict[str, Any], None, None]:
        key = f"index:{source}" if source else "index"
        for vuln_id, _ in self.valkey_client.zscan_iter(key):
            if vuln := self.get_vulnerability(vuln_id, with_meta=with_meta):
                yield vuln

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
        if not vuln_description:
            # skip a CVE without description
            return {}

        vuln_cpes = extract_cpe(vuln)
        cvss_scores = extract_cvss_cve(vuln)

        return {
            "id": vuln_id,
            "title": vuln_title,
            "description": vuln_description,
            "cpes": vuln_cpes,
            "cvss_v4_0": cvss_scores.get("cvss_v4_0", None),
            "cvss_v3_1": cvss_scores.get("cvss_v3_1", None),
            "cvss_v3_0": cvss_scores.get("cvss_v3_0", None),
            "cvss_v2_0": cvss_scores.get("cvss_v2_0", None),
        }

    def extract_ghsa(self, vuln: dict[str, Any]) -> dict[str, Any]:

        cvss_scores = extract_cvss_from_github_advisory(vuln)

        return {
            "id": vuln["id"],
            "title": strip_markdown(vuln.get("summary", "")),
            "description": strip_markdown(vuln.get("details", "")),
            "cpes": [],
            "cvss_v4_0": cvss_scores.get("cvss_v4_0", None),
            "cvss_v3_1": cvss_scores.get("cvss_v3_1", None),
            "cvss_v3_0": cvss_scores.get("cvss_v3_0", None),
            "cvss_v2_0": cvss_scores.get("cvss_v2_0", None),
        }

    def extract_pysec(self, vuln: dict[str, Any]) -> dict[str, Any]:

        cvss_scores = extract_cvss_from_pysec(vuln)

        return {
            "id": vuln["id"],
            "description": vuln["details"],
            "cpes": [],
            "cvss_v4_0": cvss_scores.get("cvss_v4_0", None),
            "cvss_v3_1": cvss_scores.get("cvss_v3_1", None),
            "cvss_v3_0": cvss_scores.get("cvss_v3_0", None),
            "cvss_v2_0": cvss_scores.get("cvss_v2_0", None),
        }

    def extract_csaf(self, vuln: dict[str, Any]) -> dict[str, Any]:

        cvss_scores = extract_cvss_from_csaf(vuln)

        description = ""
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

        return {
            "id": vuln["document"]["tracking"]["id"],
            "title": vuln["document"]["title"],
            "description": description,
            "cpes": extract_cpe_csaf(vuln),
            "cvss_v4_0": cvss_scores.get("cvss_v4_0", None),
            "cvss_v3_1": cvss_scores.get("cvss_v3_1", None),
            "cvss_v3_0": cvss_scores.get("cvss_v3_0", None),
            "cvss_v2_0": cvss_scores.get("cvss_v2_0", None),
        }

    def extract_cnvd(self, vuln: dict[str, Any]) -> dict[str, Any]:
        vuln_id = vuln.get("number", "")
        vuln_title = vuln.get("title", "").strip()
        vuln_description = strip_markdown(vuln.get("description", "").strip())
        vuln_severity = vuln.get("serverity", "").strip()

        if not vuln_description:
            # skip vulnerabilities with no description
            return {}

        if not vuln_severity:
            # skip vulnerabilities with no severity
            return {}

        return {
            "id": vuln_id,
            "title": vuln_title,
            "description": vuln_description,
            # Placeholder for CVSS scores (not available in CNVD JSON?)
            # "cvss_v4_0": None,
            # "cvss_v3_1": None,
            # "cvss_v3_0": None,
            # "cvss_v2_0": None,
            "severity": vuln_severity,  # keep typo if present in source
            # "product": vuln.get("products", {}).get("product", ""),
            # "discoverer": vuln.get("discovererName", ""),
            # "patch_name": vuln.get("patchName", ""),
            # "patch_description": vuln.get("patchDescription", ""),
            # "formal_way": vuln.get("formalWay", ""),
            # "submit_time": vuln.get("submitTime", ""),
            # "open_time": vuln.get("openTime", ""),
            # "is_event": vuln.get("isEvent", ""),
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
                case "cnvd":
                    extractor = self.extract_cnvd
                case _:
                    print(f"No parser for this source {source}.")
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
        help="Comma-separated list of sources (cnvd)",
    )
    parser.add_argument(
        "--repo-id",
        dest="repo_id",
        default="",
        help="The name of the repository you want to push your object to. It should contain your organization name when pushing to a given organization.",
    )
    parser.add_argument(
        "--commit-message",
        dest="commit_message",
        default="",
        help="Commit message when publishing",
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

    if args.repo_id:
        if args.commit_message:
            dataset_dict.push_to_hub(args.repo_id, commit_message=args.commit_message)
        else:
            dataset_dict.push_to_hub(args.repo_id)


if __name__ == "__main__":
    main()
