import argparse
import base64
import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, Generator, Optional

import requests
from datasets import load_dataset

from vulntrain.config import GITHUB_TOKEN
from vulntrain.utils import (
    strip_markdown,
)

# Logging Setup

logger = logging.getLogger("vuln_logger")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.FileHandler("vuln_extraction.log")
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def log(level: str, message: str, display: bool = False):
    level = level.lower()
    getattr(logger, level)(message)
    # if display:
    # print(f"{datetime.now().isoformat()} - {level.upper()} - {message}")


# Constants

HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"}
DEFAULT_TIMEOUT = 10
MAX_WORKERS = 16
MAX_RETRIES = 3

# VulnExtractor


class VulnExtractor:
    def __init__(self, sources: list[str], nb_rows: int):
        self.sources = sources
        self.nb_rows = nb_rows
        self.executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    def get_all(self, source: str) -> Generator[dict[str, Any], None, None]:
        page = 1
        per_page = 1000
        while True:
            url = f"https://vulnerability.circl.lu/api/vulnerability/last/{source}/{per_page}?page={page}"
            retries = 0
            while retries < MAX_RETRIES:
                try:
                    response = requests.get(
                        url,
                        headers={"accept": "application/json"},
                        timeout=DEFAULT_TIMEOUT,
                    )
                    response.raise_for_status()
                    data = response.json()
                    if not data:
                        return
                    for vuln in data:
                        yield vuln
                    page += 1
                    break
                except requests.exceptions.Timeout:
                    wait = 2**retries
                    log(
                        "warning",
                        f"[Timeout] Retrying page {page} from '{source}' in {wait}s",
                        display=True,
                    )
                    time.sleep(wait)
                    retries += 1
                except requests.RequestException as e:
                    log(
                        "error",
                        f"[Error] Failed to fetch page {page} from '{source}': {e}",
                        display=True,
                    )
                    return

    def is_url_alive(self, url: str, timeout: int = 5) -> bool:
        try:
            response = requests.head(url, timeout=timeout, allow_redirects=True)
            alive = response.status_code == 200
            log("info", f"Checked URL {url}: alive={alive}", display=True)
            return alive
        except requests.RequestException as e:
            log("warning", f"URL check failed for {url}: {e}", display=True)
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
            return self._fetch_patch_generic(url, "github", HEADERS)
        elif "gitlab.com" in url and "/-/commit/" in url:
            return self._fetch_patch_generic(url, "gitlab")
        return None

    def _fetch_patch_generic(
        self, url: str, platform: str, headers: dict[str, str] = {}
    ) -> Optional[dict[str, str]]:
        patch_url = url if url.endswith(".patch") else url + ".patch"
        try:
            response = requests.get(patch_url, headers=headers, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            patch_text = response.text.strip()
            patch_text_b64 = base64.b64encode(patch_text.encode("utf-8")).decode(
                "utf-8"
            )

            lines = patch_text.splitlines()
            commit_msg_lines = []
            for line in lines:
                if line.startswith("Subject:"):
                    commit_msg_lines.append(line.replace("Subject:", "").strip())
                elif commit_msg_lines and line.strip() == "":
                    break
                elif commit_msg_lines:
                    commit_msg_lines.append(line.strip())

            commit_message = " ".join(commit_msg_lines)
            print(f"Encoded patch (first 100 chars): {patch_text_b64[:100]}...")
            return {
                "url": url,
                # "platform": platform,
                "patch_text_b64": patch_text_b64,
                "commit_message": commit_message,
            }
        except Exception as e:
            log("error", f"{platform.upper()} patch fetch failed: {patch_url} | {e}")
            return None

    def _parallel_fetch_patches(self, urls: list[str]) -> list[dict[str, str]]:
        futures = {
            self.executor.submit(self.fetch_patch_and_message, url): url for url in urls
        }
        results = []
        for future in as_completed(futures):
            try:
                patch = future.result()
                if patch:
                    results.append(patch)
            except Exception:
                continue
        return results

    def extract_cve(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        try:
            vuln_id = vuln["cveMetadata"]["cveId"]
            title = vuln["containers"]["cna"].get("title", "")
            desc = next(
                (
                    d["value"]
                    for d in vuln["containers"]["cna"].get("descriptions", [])
                    if d["lang"].startswith("en")
                ),
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

            cwe_id, cwe_desc = "", ""
            problem_types = vuln["containers"]["cna"].get("problemTypes", [])
            if problem_types and problem_types[0].get("descriptions"):
                cwe_id = problem_types[0]["descriptions"][0].get("cweId", "").strip()
                cwe_desc = (
                    problem_types[0]["descriptions"][0].get("description", "").strip()
                )

            if not cwe_id and not cwe_desc:
                return {}

            if cwe_id and (cwe_desc.startswith(cwe_id) or cwe_id in cwe_desc):
                cwe = cwe_desc
            else:
                cwe = f"{cwe_id} - {cwe_desc}".strip(" -")

            return {
                "id": vuln_id,
                "title": title,
                "description": desc,
                "patches": patches,
                "cwe": cwe,
            }

        except Exception as e:
            log("error", f"extract_cve failed: {e}")
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

        cwe_ids = vuln.get("database_specific", {}).get("cwe_ids", [])
        if not cwe_ids:
            return {}

        return {
            "id": vuln.get("id", ""),
            "title": strip_markdown(vuln.get("summary", "")),
            "cwes": cwe_ids,
            "patch_links": patch_urls,
        }

    def extract_csaf(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        description = " ".join(
            note["text"]
            for v in vuln.get("vulnerabilities", [])
            for note in v.get("notes", [])
            if note.get("category") == "summary"
        ) or next(
            (
                note["text"]
                for note in vuln.get("document", {}).get("notes", [])
                if note.get("category") == "summary"
            ),
            "",
        )

        refs = vuln.get("document", {}).get("references", [])
        patch_urls = [
            ref.get("url", "")
            for ref in refs
            if "category" in ref and "patch" in ref["category"].lower()
        ]
        patch_urls = self.filter_alive_links(patch_urls)

        if not patch_urls:
            return {}

        cwes = []
        for v in vuln.get("vulnerabilities", []):
            cwe = v.get("cwe", {})
            cwe_id = cwe.get("id", "").strip()
            cwe_name = cwe.get("name", "").strip()
            if cwe_id and (cwe_name.startswith(cwe_id) or cwe_id in cwe_name):
                cwes.append(cwe_name)
            else:
                cwes.append(f"{cwe_id} - {cwe_name}".strip(" -"))

        if not any(cwes):
            return {}

        return {
            "id": vuln["document"]["tracking"]["id"],
            "title": vuln["document"]["title"],
            "description": description,
            "patch_links": patch_urls,
            "cwe": cwes,
        }

    def __call__(self) -> Generator[dict[str, Any], None, None]:
        print("Starting extraction loop")
        count = 0
        for source in self.sources:
            extractor = {
                "cvelistv5": self.extract_cve,
                "github": self.extract_ghsa,
                # "pysec": self.extract_pysec,
            }.get(source) or (self.extract_csaf if source.startswith("csaf_") else None)

            if not extractor:
                log("warning", f"No extractor for source '{source}'", display=True)
                continue

            for vuln in self.get_all(source):
                try:
                    vuln_data = extractor(vuln)
                    if not vuln_data or not vuln_data.get("description"):
                        continue

                    # Save each vuln to JSONL
                    with open("data.jsonl", "a", encoding="utf-8") as f:
                        json.dump(vuln_data, f)
                        f.write("\n")

                    yield vuln_data
                    count += 1
                    print(f"[{count}] Saved: {vuln_data.get('id')}")
                    log(
                        "info",
                        f"{count} - Extracted: {vuln_data.get('id')}",
                        display=True,
                    )

                    # pushing to Hugging Face every 50 examples
                    if count % 50 == 0:
                        print(f"Pushing to Hugging Face Hub at count={count}...")
                        dataset = load_dataset("json", data_files="data.jsonl")["train"]
                        dataset.push_to_hub("CIRCL/vulnerability-cwe-patch")

                except Exception as e:
                    log("error", f"Error processing vulnerability: {e}")

            if count % 50 != 0:
                print("Final push to Hugging Face with last entries ...")
                dataset = load_dataset("json", data_files="data.jsonl")["train"]
                dataset.push_to_hub("CIRCL/vulnerability-cwe-patch")


# Main
from datasets import Dataset


def main():
    if os.path.exists("data.jsonl"):
        os.remove("data.jsonl")

    # Reset the dataset on Hugging Face Hub
    empty_dataset = Dataset.from_dict(
        {
            "id": [],
            "title": [],
            "description": [],
            "patches": [],
            "cwe": [],
        }
    )
    empty_dataset.push_to_hub(
        "CIRCL/vulnerability-cwe-patch", commit_message="Reset without 'references'"
    )

    parser = argparse.ArgumentParser(description="Vulnerability Dataset Extractor")
    parser.add_argument(
        "--sources",
        required=True,
        help="Comma-separated sources (cvelistv5, github, csaf_*)",
    )
    parser.add_argument(
        "--nb-rows",
        type=int,
        default=0,
        help="Max number of vulnerabilities to process (0=all)",
    )
    args = parser.parse_args()

    sources = args.sources.split(",")
    extractor = VulnExtractor(sources, args.nb_rows)
    list(extractor())  # can also write results to a file here if needed


if __name__ == "__main__":
    main()
