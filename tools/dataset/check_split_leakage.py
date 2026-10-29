#!/usr/bin/env python3
"""Measure train/test overlap in a VulnTrain severity dataset.

Reads the parquet files of a dataset revision (for example
CIRCL/vulnerability-scores) and reports, for every split other than train:

* how many rows with a severity label have a labelled train row with the same
  description (lower-cased, whitespace collapsed; also the exact count),
* how many have a labelled train row for the same vulnerability by identifier
  or alias (``aliases`` column, or an alias file for older revisions),
* per source, and the number of description groups / vulnerability groups
  that span more than one split (0 after a group-aware split),
* identifiers that occur more than once within a source.

The severity label follows map_cvss_to_severity(score_strategy="first") of
vulntrain/trainers/classify_severity.py: the first non-null CVSS column in
schema order, then >= 9 Critical, >= 7 High, >= 4 Medium, else Low.

Optionally writes one row per test row (no text) with the twin flags, so that
any model's predictions can be split into "seen" and "unseen" rows
(see eval_seen_unseen.py).

Only pyarrow and the standard library are needed. Exit status: 0, or 1 when
more groups span splits than --max-shared-groups allows.

Example:
    hf download CIRCL/vulnerability-scores --repo-type dataset \\
        --revision main --local-dir vs
    python3 check_split_leakage.py --data-dir vs --flags-out twin_flags.csv

Contributed by Christian Bucher (https://github.com/christian140903-sudo).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq

CVSS_COLUMNS = ("cvss_v4_0", "cvss_v3_1", "cvss_v3_0", "cvss_v2_0")
SPLIT_ORDER = ("train", "validation", "test")
_WS = re.compile(r"\s+")


def severity_label(scores: list[Any]) -> str:
    """map_cvss_to_severity(score_strategy="first") on CVSS values in schema order."""
    for value in scores:
        if value is None:
            continue
        try:
            score = float(value)
        except ValueError:
            continue
        # As in the original, a NaN score would fall through to "Low".
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        return "Low"
    return ""


def text_hash(text: str, normalise: bool) -> int:
    if normalise:
        text = _WS.sub(" ", text.lower()).strip()
    return int.from_bytes(hashlib.blake2b(text.encode(), digest_size=8).digest(), "big")


def find_split_files(data_dir: Path) -> dict[str, list[Path]]:
    files: dict[str, list[Path]] = {}
    for split in SPLIT_ORDER:
        found = sorted(data_dir.rglob(f"{split}-*.parquet")) or sorted(
            data_dir.rglob(f"{split}.parquet")
        )
        if found:
            files[split] = found
    return files


def read_alias_file(path: Path) -> dict[str, list[str]]:
    """Tab-separated: identifier, comma-separated aliases."""
    aliases: dict[str, list[str]] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 2 and parts[0]:
                aliases[parts[0].upper()] = [a for a in parts[1].split(",") if a]
    return aliases


def vulnerability_keys(
    row_id: str, aliases: list[str], max_cve_aliases: int | None
) -> set[str]:
    """Identifier plus aliases, upper-cased. Aliases of rows naming more than
    max_cve_aliases CVEs (bundles) are dropped, like the patched split does."""
    keys = {a.strip().upper() for a in aliases if a and a.strip()}
    if max_cve_aliases is not None:
        if sum(k.startswith("CVE-") for k in keys) > max_cve_aliases:
            keys = set()
    if row_id:
        keys.add(row_id.strip().upper())
    return keys


def load_rows(
    files: dict[str, list[Path]],
    alias_file: dict[str, list[str]] | None,
    max_cve_aliases: int | None,
) -> tuple[list[dict[str, Any]], bool]:
    rows: list[dict[str, Any]] = []
    have_aliases = alias_file is not None
    for split, paths in files.items():
        position = 0
        for path in paths:
            schema = pq.read_schema(path)
            cvss = [name for name in schema.names if name in CVSS_COLUMNS]
            wanted = ["id", "description", "source", *cvss]
            if "aliases" in schema.names:
                wanted.append("aliases")
                have_aliases = True
            table = pq.read_table(path, columns=wanted)
            columns = {name: table.column(name).to_pylist() for name in wanted}
            del table
            for i in range(len(columns["id"])):
                row_id = str(columns["id"][i] or "")
                if "aliases" in columns:
                    aliases = list(columns["aliases"][i] or [])
                elif alias_file is not None:
                    aliases = alias_file.get(row_id.upper(), [])
                else:
                    aliases = []
                text = str(columns["description"][i] or "")
                rows.append(
                    {
                        "split": split,
                        "row_index": position,
                        "id": row_id,
                        "source": str(columns["source"][i] or ""),
                        "label": severity_label([columns[c][i] for c in cvss]),
                        "norm": text_hash(text, True),
                        "exact": text_hash(text, False),
                        "keys": vulnerability_keys(row_id, aliases, max_cve_aliases),
                    }
                )
                position += 1
            del columns
    return rows, have_aliases


def components(rows: list[dict[str, Any]], use_keys: bool) -> list[int]:
    """Connected components over shared description (and identifiers/aliases),
    computed by breadth-first search on the row-key graph."""
    by_key: dict[Any, list[int]] = defaultdict(list)
    for index, row in enumerate(rows):
        by_key[("t", row["norm"])].append(index)
        if use_keys:
            for key in row["keys"]:
                by_key[("k", key)].append(index)
    row_keys: list[list[Any]] = [[] for _ in rows]
    for key, members in by_key.items():
        if len(members) > 1:
            for index in members:
                row_keys[index].append(key)
    component = [-1] * len(rows)
    done_keys: set[Any] = set()
    for start in range(len(rows)):
        if component[start] != -1:
            continue
        component[start] = start
        queue = [start]
        while queue:
            current = queue.pop()
            for key in row_keys[current]:
                if key in done_keys:
                    continue
                done_keys.add(key)
                for other in by_key[key]:
                    if component[other] == -1:
                        component[other] = start
                        queue.append(other)
    return component


def shared_groups(rows: list[dict[str, Any]], component: list[int]) -> int:
    splits_of: dict[int, set[str]] = defaultdict(set)
    for index, row in enumerate(rows):
        splits_of[component[index]].add(row["split"])
    return sum(1 for s in splits_of.values() if len(s) > 1)


def pct(part: int, whole: int) -> float:
    return round(100.0 * part / whole, 2) if whole else 0.0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument(
        "--aliases",
        type=Path,
        help="alias file (id<TAB>alias,alias) for revisions without an aliases column",
    )
    parser.add_argument(
        "--max-cve-aliases",
        type=int,
        default=1,
        help="ignore aliases of rows naming more CVEs than this (-1: no limit)",
    )
    parser.add_argument("--flags-out", type=Path, help="per-row twin flags (CSV)")
    parser.add_argument("--flags-split", default="test")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--max-shared-groups", type=int, default=None)
    args = parser.parse_args()

    files = find_split_files(args.data_dir)
    if "train" not in files:
        print(f"No train-*.parquet found under {args.data_dir}", file=sys.stderr)
        return 2
    alias_file = read_alias_file(args.aliases) if args.aliases else None
    limit = None if args.max_cve_aliases < 0 else args.max_cve_aliases
    rows, have_aliases = load_rows(files, alias_file, limit)

    train = [r for r in rows if r["split"] == "train"]
    train_norm = {r["norm"] for r in train if r["label"]}
    train_exact = {r["exact"] for r in train if r["label"]}
    train_keys: set[str] = set()
    for r in train:
        if r["label"]:
            train_keys |= r["keys"]

    report: dict[str, Any] = {
        "files": {s: [p.name for p in ps] for s, ps in files.items()},
        "rows": dict(Counter(r["split"] for r in rows)),
        "labelled_rows": dict(Counter(r["split"] for r in rows if r["label"])),
        "alias_data": have_aliases,
        "splits": {},
    }
    flags: list[dict[str, Any]] = []
    for split in files:
        if split == "train":
            continue
        per_source: dict[str, Counter[str]] = defaultdict(Counter)
        for r in rows:
            if r["split"] != split:
                continue
            twin = r["norm"] in train_norm
            exact = r["exact"] in train_exact
            alias = bool(r["keys"] & train_keys) if have_aliases else None
            if split == args.flags_split:
                flags.append(
                    {
                        "row_index": r["row_index"],
                        "id": r["id"],
                        "source": r["source"],
                        "severity_label": r["label"],
                        "text_twin": int(twin),
                        "exact_text_twin": int(exact),
                        "alias_twin": "" if alias is None else int(alias),
                    }
                )
            if not r["label"]:
                continue
            for name in (r["source"], "ALL"):
                c = per_source[name]
                c["labelled"] += 1
                c["text_twin"] += twin
                c["exact_text_twin"] += exact
                if alias is not None:
                    c["alias_twin"] += alias
                    c["text_or_alias_twin"] += twin or alias
                    c["alias_twin_without_text_twin"] += alias and not twin
        table: dict[str, dict[str, float]] = {}
        for name, c in sorted(per_source.items(), key=lambda kv: -kv[1]["labelled"]):
            entry: dict[str, float] = dict(c)
            for key in list(c):
                if key != "labelled":
                    entry[f"{key}_pct"] = pct(c[key], c["labelled"])
            table[name] = entry
        report["splits"][split] = table

    id_splits: dict[tuple[str, str], list[str]] = defaultdict(list)
    for r in rows:
        id_splits[(r["source"], r["id"].lower())].append(r["split"])
    dup = {k: v for k, v in id_splits.items() if len(v) > 1}
    report["duplicate_ids"] = {
        "ids": len(dup),
        "extra_rows": sum(len(v) - 1 for v in dup.values()),
        "by_source": dict(Counter(k[0] for k in dup)),
        "across_splits": sum(1 for v in dup.values() if len(set(v)) > 1),
    }
    report["shared_description_groups"] = shared_groups(rows, components(rows, False))
    if have_aliases:
        report["shared_vulnerability_groups"] = shared_groups(
            rows, components(rows, True)
        )

    print(json.dumps(report, indent=1))
    if args.json_out:
        args.json_out.write_text(json.dumps(report, indent=1) + "\n")
    if args.flags_out:
        with args.flags_out.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(flags[0]))
            writer.writeheader()
            writer.writerows(flags)
    if args.max_shared_groups is not None:
        shared = report.get(
            "shared_vulnerability_groups", report["shared_description_groups"]
        )
        if shared > args.max_shared_groups:
            print(f"FAIL: {shared} groups span splits", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
