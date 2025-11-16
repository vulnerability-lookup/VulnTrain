import argparse
import asyncio
import base64

# import json
import logging
import time
from typing import Optional

import aiohttp
from aiohttp import ClientSession, ClientTimeout
from datasets import (  # add this at the top with your imports
    Dataset,
    DatasetDict,
    load_dataset,
)

from vulntrain.config import GITHUB_TOKEN
from vulntrain.utils import strip_markdown

# ---------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------

logger = logging.getLogger("vuln_logger")
logger.setLevel(logging.INFO)

# Only create handler if none exist
if not logger.handlers:
    handler = logging.FileHandler("vuln_extraction.log")
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# Keep the formatter for display
display_formatter = formatter


def log(level: str, message: str, display: bool = False):
    log_method = getattr(logger, level.lower())
    log_method(message)

    if display:
        # Create a LogRecord manually and format it
        record = logging.LogRecord(
            name=logger.name,
            level=getattr(logging, level.upper()),
            pathname="",
            lineno=0,
            msg=message,
            args=None,
            exc_info=None,
        )
        print(display_formatter.format(record))


def normalize_patch_url(url: str) -> str:
    """
    Normalize commit/patch URLs to match how they are stored in patch_map.
    """
    # --- GitHub ---
    if "github.com" in url and "/commit/" in url:
        before, after = url.split("/commit/", 1)
        sha = (
            after.split("/", 1)[0]  # remove trailing path
            .split("?", 1)[0]  # remove query
            .split("#", 1)[0]  # remove fragment
        )
        return f"{before}/commit/{sha}.patch"

    # --- GitLab ---
    if "gitlab.com" in url and "/-/commit/" in url:
        return url.split(".patch")[0]

    # --- Bitbucket ---
    if "bitbucket.org" in url and "commits" in url:
        return url.rstrip("/raw")

    return url


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

HEADERS = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/json"}
DEFAULT_TIMEOUT = 10
MAX_CONCURRENT_REQUESTS = 10
MAX_RETRIES = 3
HUGGINGFACE_BATCH = 5000000


# ---------------------------------------------------------------------
# Async Extractor Class
# ---------------------------------------------------------------------


class VulnExtractor:
    def __init__(self, sources: list[str], repo_id: str, nb_rows: int):
        self.sources = sources
        self.repo_id = repo_id
        self.nb_rows = nb_rows
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        self.timeout = ClientTimeout(total=DEFAULT_TIMEOUT)

    # -------------------------------
    # Helper: incremental push to Hub
    # -------------------------------
    def push_to_hub_incremental(self, vuln_list, total_count):
        commit_message = f"[DATASET] Added {len(vuln_list)} new vulnerabilities (total {total_count})"
        log(
            "info",
            f"Pushing {len(vuln_list)} vulnerabilities to {self.repo_id} ({commit_message})",
            display=True,
        )

        # Convert new data to a temporary dataset
        new_dataset = Dataset.from_list(vuln_list)
        new_dataset_dict = new_dataset.train_test_split(test_size=0.1)
        new_dataset_dict = DatasetDict(
            {
                "train": new_dataset_dict["train"],
                "test": new_dataset_dict["test"],
            }
        )

        # Load the existing dataset (if any) from the hub
        try:
            existing = load_dataset(self.repo_id)
            log(
                "info",
                f"Loaded existing dataset with {len(existing['train'])} train / {len(existing['test'])} test samples.",
                display=True,
            )

            # Concatenate old + new data
            combined_train = Dataset.from_dict(existing["train"].to_dict()).concatenate(
                new_dataset_dict["train"]
            )
            combined_test = Dataset.from_dict(existing["test"].to_dict()).concatenate(
                new_dataset_dict["test"]
            )
            final_dataset_dict = DatasetDict(
                {"train": combined_train, "test": combined_test}
            )

        except Exception:
            # If first push
            log(
                "info",
                "No existing dataset found on the Hub — creating a new one.",
                display=True,
            )
            final_dataset_dict = new_dataset_dict

        # Push the updated dataset to the same repo (one consistent dataset)
        final_dataset_dict.push_to_hub(
            self.repo_id,
            commit_message=commit_message,
            private=False,
            max_shard_size="1GB",
        )

        print(final_dataset_dict)

        # Clear temp to save memory
        del new_dataset, new_dataset_dict, final_dataset_dict

    # -------------------------------
    # Generic fetch helper
    # -------------------------------
    async def fetch_json(
        self, session: ClientSession, url: str
    ) -> Optional[list[dict]]:
        for attempt in range(MAX_RETRIES):
            try:
                async with self.semaphore:
                    async with session.get(url, timeout=self.timeout) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        elif resp.status == 404:
                            return None
            except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                log("warning", f"[Retry {attempt+1}/{MAX_RETRIES}] {url} failed: {e}")
                await asyncio.sleep(2**attempt)
        return None

    # -------------------------------
    # Fetch all vulnerabilities
    # -------------------------------
    async def get_all(self, session: ClientSession, source: str):
        page = 1
        per_page = 100
        while True:
            url = f"https://vulnerability.circl.lu/api/vulnerability/?source={source}&per_page={per_page}&page={page}"
            data = await self.fetch_json(session, url)
            if not data:
                break
            for vuln in data:
                yield vuln
            page += 1

    # -------------------------------
    # Async fetch of patch
    # -------------------------------
    async def fetch_patch_and_message(
        self, session: ClientSession, url: str
    ) -> Optional[dict[str, str]]:
        if "github.com" in url and "/commit/" in url:
            patch_headers = {
                "Authorization": f"token {GITHUB_TOKEN}",
                "Accept": "application/vnd.github.v3.patch",
            }
            patch_url = url if url.endswith(".patch") else url + ".patch"
        elif "gitlab.com" in url and "/-/commit/" in url:
            patch_headers = {"Accept": "text/plain"}
            patch_url = url if url.endswith(".patch") else url + ".patch"
        elif "bitbucket.org" in url and "commits" in url:
            patch_headers = {"Accept": "text/plain"}
            patch_url = url if url.endswith("/raw") else url + "/raw"
        else:
            log("warning", f"Unknown patch URL format: {url}", display=True)
            return None

        for attempt in range(MAX_RETRIES):
            try:
                async with self.semaphore:
                    async with session.get(
                        patch_url, headers=patch_headers, timeout=self.timeout
                    ) as resp:
                        # --- Log GitHub rate limits ---
                        if "x-ratelimit-remaining" in resp.headers:
                            remaining = resp.headers.get("x-ratelimit-remaining")
                            limit = resp.headers.get("x-ratelimit-limit")
                            reset = resp.headers.get("x-ratelimit-reset")
                            reset_time = time.strftime(
                                "%Y-%m-%d %H:%M:%S", time.localtime(int(reset))
                            )
                            log(
                                "info",
                                f"GitHub RateLimit: {remaining}/{limit}, reset at {reset_time}",
                                display=True,
                            )

                        if (
                            resp.status == 403
                            and "x-ratelimit-remaining" in resp.headers
                            and resp.headers["x-ratelimit-remaining"] == "0"
                        ):
                            reset_sec = int(
                                resp.headers.get("x-ratelimit-reset", time.time() + 60)
                            ) - int(time.time())
                            log(
                                "warning",
                                f"Rate limit reached. Sleeping {reset_sec} seconds.",
                                display=True,
                            )
                            await asyncio.sleep(reset_sec + 1)
                            continue

                        if resp.status != 200:
                            log(
                                "warning",
                                f"Failed fetch [{resp.status}] for {patch_url} (attempt {attempt+1})",
                                display=True,
                            )
                            await asyncio.sleep(2**attempt)
                            continue

                        patch_text = (await resp.text()).strip()
                        if not patch_text:
                            log(
                                "warning",
                                f"Empty patch content: {patch_url}",
                                display=True,
                            )
                            return None

                        patch_text_b64 = base64.b64encode(
                            patch_text.encode("utf-8")
                        ).decode("utf-8")

                        # Extract commit message
                        commit_msg_lines = []
                        for line in patch_text.splitlines():
                            if line.startswith("Subject:"):
                                commit_msg_lines.append(
                                    line.replace("Subject:", "").strip()
                                )
                                continue
                            if line.startswith("From:") or line.startswith("Date:"):
                                continue
                            if line.startswith("diff --git"):
                                break
                            if (
                                not commit_msg_lines
                                and line.strip()
                                and not line.startswith("From ")
                            ):
                                commit_msg_lines.append(line.strip())
                            elif (
                                commit_msg_lines
                                and line.strip()
                                and not line.startswith("---")
                            ):
                                commit_msg_lines.append(line.strip())
                        commit_message = " ".join(commit_msg_lines).strip()

                        log(
                            "info",
                            f"Successfully fetched patch: {url} | Commit message: {commit_message[:60]}...",
                            display=True,
                        )

                        # Delay to reduce request aggression
                        await asyncio.sleep(1)
                        return {
                            "url": url,
                            "patch_text_b64": patch_text_b64,
                            "commit_message": commit_message,
                        }

            except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                log(
                    "warning",
                    f"[Retry {attempt+1}/{MAX_RETRIES}] {patch_url} failed: {e}",
                    display=True,
                )
                await asyncio.sleep(2**attempt)

        log(
            "error",
            f"Failed to fetch patch after {MAX_RETRIES} attempts: {patch_url}",
            display=True,
        )
        return None

    # -------------------------------
    # Batch patch fetching (global)
    # -------------------------------
    async def batch_fetch_patches(
        self, session: ClientSession, urls: set[str]
    ) -> dict[str, dict]:
        log("info", f"Starting batch fetch for {len(urls)} patches...", display=True)
        tasks = [self.fetch_patch_and_message(session, url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        patch_map = {}
        success_count = 0
        fail_count = 0
        for res in results:
            if isinstance(res, dict) and res.get("url"):
                patch_map[res["url"]] = res
                success_count += 1
            else:
                fail_count += 1
        log(
            "info",
            f"Batch fetch complete. Success: {success_count}, Failures: {fail_count}",
            display=True,
        )
        return patch_map

    # -------------------------------
    # Main async loop
    # -------------------------------
    async def run(self):
        log("info", "Starting main async loop", display=True)
        async with aiohttp.ClientSession(headers=HEADERS) as session:
            count = 0
            all_vulns_list = []  # collect all extracted vulnerabilities

            for source in self.sources:
                # 1 Fetch all vulnerabilities
                all_vulns = []
                async for vuln in self.get_all(session, source):
                    vuln_id = vuln.get("cveMetadata", {}).get("cveId") or vuln.get("id")
                    if vuln_id:
                        all_vulns.append(vuln)
                    if 0 < self.nb_rows <= len(all_vulns):
                        break

                log(
                    "info",
                    f"Collected {len(all_vulns)} new vulnerabilities from {source}.",
                    display=True,
                )

                # 2 Collect all unique patch URLs
                patch_urls = set()
                for vuln in all_vulns:
                    if source == "cvelistv5":
                        refs = (
                            vuln.get("containers", {})
                            .get("cna", {})
                            .get("references", [])
                        )
                    else:
                        refs = vuln.get("references", [])
                    for ref in refs:
                        url = ref.get("url")
                        if url:
                            patch_urls.add(normalize_patch_url(url))

                log(
                    "info",
                    f"Found {len(patch_urls)} unique patch URLs to fetch...",
                    display=True,
                )

                # 3 Fetch all patches concurrently
                patch_map = await self.batch_fetch_patches(session, patch_urls)

                # 4 Process vulnerabilities with pre-fetched patches
                for vuln in all_vulns:
                    vuln_id = vuln.get("cveMetadata", {}).get("cveId") or vuln.get("id")
                    if not vuln_id:
                        continue

                    if source == "cvelistv5":
                        patches = [
                            patch_map.get(normalize_patch_url(ref.get("url")))
                            for ref in vuln["containers"]["cna"].get("references", [])
                            if normalize_patch_url(ref.get("url")) in patch_map
                        ]

                        if not patches:
                            continue

                        problem_types = vuln["containers"]["cna"].get(
                            "problemTypes", []
                        )
                        if problem_types and problem_types[0].get("descriptions"):
                            desc_data = problem_types[0]["descriptions"][0]
                            cwe_id = desc_data.get("cweId", "").strip()
                            cwe_desc = desc_data.get("description", "").strip()
                            cwe = cwe_desc or cwe_id or "UNKNOWN"

                        desc = next(
                            (
                                d["value"]
                                for d in vuln["containers"]["cna"].get(
                                    "descriptions", []
                                )
                                if d["lang"].startswith("en")
                            ),
                            vuln["containers"]["cna"].get("title", "No description"),
                        )

                        vuln_data = {
                            "id": vuln_id,
                            "title": vuln["containers"]["cna"].get("title", ""),
                            "description": desc,
                            "patches": patches,
                            "cwe": cwe,
                        }

                    else:  # GHSA
                        patches = [
                            patch_map.get(normalize_patch_url(ref.get("url")))
                            for ref in vuln.get("references", [])
                            if normalize_patch_url(ref.get("url")) in patch_map
                        ]

                        if not patches:
                            continue
                        cwe_ids = vuln.get("database_specific", {}).get("cwe_ids", [])
                        # if not cwe_ids:
                        #     continue
                        vuln_data = {
                            "id": vuln.get("id", ""),
                            "title": strip_markdown(vuln.get("summary", "")),
                            "patches": patches,
                            "cwes": cwe_ids,
                        }

                    # if not vuln_data.get("description"):
                    #     continue

                    all_vulns_list.append(vuln_data)
                    count += 1

                    if count % HUGGINGFACE_BATCH == 0:
                        self.push_to_hub_incremental(all_vulns_list, count)
                        all_vulns_list.clear()

                    log("info", f"[{count}] Collected: {vuln_id}", display=True)

            # Push remaining data
            if all_vulns_list:
                self.push_to_hub_incremental(all_vulns_list, count)
            # -------------------------------
            # Create train/test split and push
            # -------------------------------
            # dataset = Dataset.from_list(all_vulns_list)
            # dataset_dict = dataset.train_test_split(test_size=0.1)
            # dataset_dict = DatasetDict(
            #     {"train": dataset_dict["train"], "test": dataset_dict["test"]}
            # )

            # print(dataset_dict)

            # Push train and test to Hugging Face
            # dataset_dict["train"].push_to_hub(self.repo_id, path_in_repo="train")
            # dataset_dict["test"].push_to_hub(self.repo_id, path_in_repo="test")
            # dataset_dict.push_to_hub(self.repo_id)
            log(
                "info",
                "Finished pushing train/test splits to Hugging Face Hub.",
                display=True,
            )


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Optimized Async & Resumable Vulnerability Dataset Extractor"
    )
    parser.add_argument(
        "--sources",
        required=True,
        help="Comma-separated sources (e.g., cvelistv5,github)",
    )
    parser.add_argument(
        "--repo-id", dest="repo_id", default="CIRCL/vulnerability-cwe-patch"
    )
    parser.add_argument(
        "--nb-rows", type=int, default=0, help="Max vulnerabilities to process (0=all)"
    )
    args = parser.parse_args()

    extractor = VulnExtractor(args.sources.split(","), args.repo_id, args.nb_rows)
    asyncio.run(extractor.run())


if __name__ == "__main__":
    main()
