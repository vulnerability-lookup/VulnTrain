"""
Creates a text/description dataset using vulnerabilities description from Vulnerability-Lookup.

Author: Cédric Bonhomme / CIRCL

"""

import argparse
import json
from typing import Any, Generator

import valkey
from datasets import Dataset, DatasetDict  # type: ignore[import-untyped]

from vulntrain.conf import hf_token, valkey_host, valkey_port
from vulntrain.utils import strip_markdown


class VulnExtractor:
    def __init__(self, sources, nb_rows):
        self.sources = sources
        self.nb_rows = nb_rows
        self.valkey_client = valkey.Valkey(
            host=valkey_host,
            port=valkey_port,
            decode_responses=True,
        )

    def get_vulnerability_meta(
        self, vulnerability_id: str
    ) -> dict[str, str | dict[str, Any]]:
        _vid = vulnerability_id.lower()
        to_return: dict[str, str | dict[str, Any]] = {}
        for meta_name, meta_uuid in self.valkey_client.hgetall(f"{_vid}:meta").items():
            if self.valkey_client.exists(f"{meta_name}:{meta_uuid}"):
                if self.valkey_client.type(f"{meta_name}:{meta_uuid}") == "string":  # type: ignore[no-untyped-call]  # noqa
                    if _meta_str := self.valkey_client.get(f"{meta_name}:{meta_uuid}"):
                        to_return[meta_name] = _meta_str
                elif self.valkey_client.type(f"{meta_name}:{meta_uuid}") == "hash":  # type: ignore[no-untyped-call]  # noqa
                    if _meta_hash := self.valkey_client.hgetall(
                        f"{meta_name}:{meta_uuid}"
                    ):
                        to_return[meta_name] = _meta_hash
            else:
                print(f"Unable to find meta {meta_uuid} for {meta_name}")
        return to_return

    def get_vulnerability(
        self, vulnerability_id: str, *, with_meta: bool | None = False
    ) -> dict[str, Any] | None:
        _vid = vulnerability_id.lower()
        _vuln = self.valkey_client.get(_vid)
        if not _vuln:
            return None
        vuln = json.loads(_vuln)
        if with_meta:
            if meta := self.get_vulnerability_meta(_vid):
                vuln["vulnerability-lookup:meta"] = meta
        return vuln

    def get_all(
        self, source: str = "", /, with_meta: bool = False
    ) -> Generator[dict[str, Any], None, None]:
        """This method will scan a complete source and yield the vulnerabilities.
        It is up to the caller to handle the yielded entries as it will be a lot"""
        if source:
            key = f"index:{source}"
        else:
            key = "index"
        for vuln_id, _ in self.valkey_client.zscan_iter(key):
            if vuln := self.get_vulnerability(vuln_id, with_meta=with_meta):
                yield vuln

    def extract_cve(self, vuln):
        #
        # CVE id, title, and description
        #
        vuln_id = vuln["cveMetadata"]["cveId"]
        vuln_title = vuln["containers"]["cna"].get("title", "")
        # if not vuln_title:
        #     for entry in vuln["containers"].get("adp", []):
        #         if "title" in entry:
        #             vuln_title = entry.get("title")
        #             break
        #     else:
        #         vuln_title = ""
        for description in vuln["containers"]["cna"].get("descriptions", []):
            if description["lang"].lower() in ["eng", "en", "en-en", "en-us"]:
                vuln_description = description["value"]
                break
        else:
            return {}

        #
        # CPE
        #

        # vulnrichement
        vuln_cpes = []
        if vulnrichment := vuln.get("vulnerability-lookup:meta", {}).get(
            "vulnrichment", False
        ):
            containers = json.loads(vulnrichment["containers"])

            # Check ADP section
            if "adp" in containers:
                for entry in containers["adp"]:
                    if "affected" in entry:
                        for affected in entry["affected"]:
                            if "cpes" in affected:
                                vuln_cpes.extend(affected["cpes"])

            # Check CNA section
            if "cna" in containers and "affected" in containers["cna"]:
                for affected in containers["cna"]["affected"]:
                    if "cpes" in affected:
                        vuln_cpes.extend(affected["cpes"])

        # fkie
        if fkie := vuln.get("vulnerability-lookup:meta", {}).get("fkie_nvd", False):
            if "configurations" in fkie:
                configurations = json.loads(fkie["configurations"])
                for config in configurations:
                    if "nodes" in config:
                        for node in config["nodes"]:
                            if "cpeMatch" in node:
                                vuln_cpes.extend(
                                    match["criteria"]
                                    for match in node["cpeMatch"]
                                    if "criteria" in match
                                )

        # default container
        for elem in vuln["containers"]["cna"]["affected"]:
            if "cpes" in elem:
                vuln_cpes.extend(elem["cpes"])

        vuln_cpes = list(dict.fromkeys(cpe.lower() for cpe in vuln_cpes))

        vuln_data = {
            "id": vuln_id,
            "title": vuln_title,
            "description": vuln_description,
            "cpes": vuln_cpes,
        }

        return vuln_data

    def extract_github(self, vuln):
        vuln_id = vuln["id"]
        vuln_title = strip_markdown(vuln.get("summary", ""))
        vuln_description = strip_markdown(vuln.get("details", ""))
        vuln_data = {
            "id": vuln_id,
            "title": vuln_title,
            "description": vuln_description,
            "cpes": [],
        }

        return vuln_data

    def __call__(self):
        count = 0
        for source in self.sources:
            for vuln in self.get_all(source, True):
                match source:
                    case "cvelistv5":
                        vuln_data = self.extract_cve(vuln)
                    case "github":
                        vuln_data = self.extract_github(vuln)
                    case _:
                        raise Exception("Unknown source.")

                if not vuln_data.get("description", ""):
                    continue

                yield vuln_data

                count += 1
                if count == self.nb_rows:
                    return


def main():
    parser = argparse.ArgumentParser(description="Dataset generation.")
    parser.add_argument(
        "--sources",
        dest="sources",
        required=True,
        default="The Vulnerability-Lookup sources of vulnerability advisories. List of sources (cvelistv5, github) separated by a coma.",
    )
    parser.add_argument(
        "--upload",
        action="store_true",
        help="Upload to HuggingFace.",
        default=False,
    )
    parser.add_argument(
        "--repo-id",
        dest="repo_id",
        help="Repo id.",
        default="The id/name of the destination repository for the dataset.",
    )
    parser.add_argument(
        "--commit-message",
        dest="commit_message",
        type=str,
        help="Commit message when publishing.",
        default="",
    )
    parser.add_argument(
        "--nb-rows",
        dest="nb_rows",
        type=int,
        help="Number of rows in the dataset.",
        default=0,
    )

    args = parser.parse_args()

    sources = []
    if args.sources:
        sources = args.sources.split(",")

    extractor = VulnExtractor(sources, args.nb_rows)

    vulns = list(extractor())

    def gen():
        for vuln in vulns:
            yield vuln

    dataset = Dataset.from_generator(gen)
    train_test_split = dataset.train_test_split(test_size=0.1)
    dataset_dict = DatasetDict(
        {"train": train_test_split["train"], "test": train_test_split["test"]}
    )

    print(dataset_dict)
    if args.upload:
        if hf_token:
            dataset_dict.push_to_hub(args.repo_id, commit_message=args.commit_message)
        else:
            dataset_dict.push_to_hub(
                args.repo_id, commit_message=args.commit_message, token=hf_token
            )


if __name__ == "__main__":
    main()
