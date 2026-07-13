"""Refresh the local CWE knowledge base from the Vulnerability-Lookup API.

Produces two files next to this script:

- ``vulnerability.circl.lu.json``: raw CWE records (paginated list endpoint),
  used to build the parent/child relationships.
- ``cwe_usage.json``: per-CWE mapping usage from ``Mapping_Notes`` (Allowed,
  Allowed-with-Review, Discouraged, Prohibited), fetched from the per-ID
  endpoint. Used to avoid training the CWE classifier on discouraged CWEs.
"""

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

API_ROOT = "https://vulnerability.circl.lu/api/cwe/"
PER_PAGE = 100
WORKERS = 8

HERE = Path(__file__).parent


def fetch_all_cwes(session: requests.Session) -> list[dict]:
    records = []
    page = 1
    while True:
        response = session.get(
            API_ROOT, params={"page": page, "per_page": PER_PAGE}, timeout=30
        )
        response.raise_for_status()
        payload = response.json()
        records.extend(payload["data"])
        if page * PER_PAGE >= payload["metadata"]["count"]:
            return records
        page += 1


def fetch_usage(session: requests.Session, cwe_id: str) -> tuple[str, dict]:
    response = session.get(f"{API_ROOT}{cwe_id}", timeout=30)
    response.raise_for_status()
    record = response.json()
    mapping_notes = record.get("Mapping_Notes") or {}
    return cwe_id, {
        "name": record.get("@Name", ""),
        "abstraction": record.get("@Abstraction", ""),
        "usage": mapping_notes.get("Usage", ""),
    }


def main() -> None:
    session = requests.Session()
    session.headers["accept"] = "application/json"

    print("Fetching CWE list...")
    records = fetch_all_cwes(session)
    print(f"  {len(records)} CWE records")
    with open(HERE / "vulnerability.circl.lu.json", "w") as f:
        json.dump({"metadata": {"count": len(records)}, "data": records}, f, indent=2)

    print("Fetching per-CWE mapping usage...")
    cwe_ids = [record["@ID"] for record in records]
    usage = {}
    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        for cwe_id, info in executor.map(
            lambda cid: fetch_usage(session, cid), cwe_ids
        ):
            usage[cwe_id] = info

    missing = sorted(cid for cid, info in usage.items() if not info["usage"])
    if missing:
        print(f"  warning: no Mapping_Notes/Usage for {len(missing)} CWEs: {missing}")

    with open(HERE / "cwe_usage.json", "w") as f:
        json.dump(dict(sorted(usage.items(), key=lambda kv: int(kv[0]))), f, indent=2)

    counts: dict[str, int] = {}
    for info in usage.values():
        counts[info["usage"] or "unknown"] = counts.get(info["usage"] or "unknown", 0) + 1
    print("Usage breakdown:", counts)


if __name__ == "__main__":
    main()
