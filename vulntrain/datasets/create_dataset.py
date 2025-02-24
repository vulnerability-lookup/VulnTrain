import argparse
import json
from typing import Any, Generator

import valkey
from datasets import Dataset, DatasetDict  # type: ignore[import-untyped]

from vulntrain.config import hf_token, valkey_host, valkey_port
from vulntrain.utils import strip_markdown, extract_cpe, extract_cvss_cve, extract_cvss_from_github_advisory


class VulnExtractor:
    def __init__(self, sources: list[str], nb_rows: int):
        self.sources = sources
        self.nb_rows = nb_rows
        self.valkey_client = valkey.Valkey(host=valkey_host, port=valkey_port, decode_responses=True)
        self.cvss_severity_mapping = {
            "Low": (0.1, 3.9),
            "Medium": (4.0, 6.9),
            "High": (7.0, 8.9),
            "Critical": (9.0, 10.0),
        }

    def classify_cvss(self, score: float) -> str:
        """Convert a CVSS score (0-10) into a severity category."""
        for severity, (low, high) in self.cvss_severity_mapping.items():
            if low <= score <= high:
                return severity
        return "Unknown"

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

    def get_vulnerability(self, vulnerability_id: str, with_meta: bool = False) -> dict[str, Any] | None:
        _vid = vulnerability_id.lower()
        _vuln = self.valkey_client.get(_vid)
        if not _vuln:
            return None
        
        vuln = json.loads(_vuln)
        if with_meta:
            vuln["vulnerability-lookup:meta"] = self.get_vulnerability_meta(_vid)
        
        return vuln

    def get_all(self, source: str, with_meta: bool = False) -> Generator[dict[str, Any], None, None]:
        key = f"index:{source}" if source else "index"
        for vuln_id, _ in self.valkey_client.zscan_iter(key):
            if vuln := self.get_vulnerability(vuln_id, with_meta=with_meta):
                yield vuln

    def extract_cve(self, vuln: dict[str, Any]) -> dict[str, Any]:
        vuln_id = vuln["cveMetadata"]["cveId"]
        vuln_title = vuln["containers"]["cna"].get("title", "")
        vuln_description = next(
            (desc["value"] for desc in vuln["containers"]["cna"].get("descriptions", []) if desc["lang"].startswith("en")), ""
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
        return {
            "id": vuln["id"],
            "title": strip_markdown(vuln.get("summary", "")),
            "description": strip_markdown(vuln.get("details", "")),
            "cpes": [],
            **extract_cvss_from_github_advisory(vuln),
        }

    def __call__(self) -> Generator[dict[str, Any], None, None]:
        count = 0
        for source in self.sources:
            for vuln in self.get_all(source, True):
                extractor = self.extract_cve if source == "cvelistv5" else self.extract_ghsa
                vuln_data = extractor(vuln)
                
                if not vuln_data.get("description"):
                    continue
                
                yield vuln_data

                count += 1
                if count == self.nb_rows:
                    return


def main():
    parser = argparse.ArgumentParser(description="Dataset generation.")
    parser.add_argument("--sources", required=True, help="Comma-separated list of sources (cvelistv5, github)")
    parser.add_argument("--upload", action="store_true", help="Upload dataset to Hugging Face")
    parser.add_argument("--repo-id", required=False, help="Hugging Face repository ID")
    parser.add_argument("--commit-message", default="", help="Commit message when publishing")
    parser.add_argument("--nb-rows", type=int, default=0, help="Number of rows in the dataset")
    
    args = parser.parse_args()
    
    sources = args.sources.split(",")
    extractor = VulnExtractor(sources, args.nb_rows)
    vulns = list(extractor())
    
    dataset = Dataset.from_list(vulns)
    dataset_dict = dataset.train_test_split(test_size=0.1)
    
    dataset_dict = DatasetDict({"train": dataset_dict["train"], "test": dataset_dict["test"]})
    print(dataset_dict)
    
    if args.upload:
        # dataset_dict.push_to_hub(args.repo_id, commit_message=args.commit_message, token=hf_token)
        dataset_dict.push_to_hub(args.repo_id)


if __name__ == "__main__":
    main()
