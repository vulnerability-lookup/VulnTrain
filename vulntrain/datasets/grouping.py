"""Group-aware splitting of vulnerability datasets.

The same vulnerability is often present in several sources: a CVE record and
the GitHub advisory that copies (or rewrites) its description, several Red Hat
errata for one CVE, or one CSAF document listed twice in the source index. A
random row split puts one copy in train and the other in test, so the test
score partly measures how well the model recalls rows it has already seen.

The helpers below put rows into one group when they share a normalised
description, an identifier or an alias, and assign whole groups to a split.
The split of a group is derived from a hash of its smallest identifier, so a
vulnerability stays in the same split when the dataset is regenerated.
"""

import hashlib
import re
from collections.abc import Iterable, Sequence
from typing import Any

_WHITESPACE = re.compile(r"\s+")

# Fields holding other identifiers of the same vulnerability.
ALIAS_FIELDS = ("aliases", "cve_id", "cve_ids")
# A record naming several CVEs (a vendor roll-up, a kernel erratum) is a bundle,
# not another name of one vulnerability: linking through it would chain
# unrelated vulnerabilities into one large group. Its aliases are ignored.
MAX_CVE_ALIASES = 1


def normalize_description(text: str) -> str:
    """Lower-case a description and collapse every run of whitespace."""
    return _WHITESPACE.sub(" ", text.lower()).strip()


def extract_aliases(vuln: dict[str, Any], source: str) -> list[str]:
    """Return the other identifiers listed in a raw vulnerability record.

    GitHub and PySec advisories (OSV format) carry an ``aliases`` list. CSAF
    documents name their CVEs in ``vulnerabilities[].cve``. CVE records are
    their own identifier and return an empty list.
    """
    aliases: list[str] = []
    if source in ("github", "pysec"):
        aliases = [alias for alias in vuln.get("aliases") or [] if alias]
    elif source.startswith("csaf_"):
        aliases = [
            entry["cve"]
            for entry in vuln.get("vulnerabilities") or []
            if isinstance(entry, dict) and entry.get("cve")
        ]
    return sorted({str(alias) for alias in aliases})


def _link_keys(row: dict[str, Any]) -> list[str]:
    """Identifiers of a row: its own id plus its aliases (see MAX_CVE_ALIASES)."""
    aliases: list[str] = []
    for field in ALIAS_FIELDS:
        value = row.get(field)
        if isinstance(value, str):
            aliases.append(value)
        elif isinstance(value, Iterable):
            aliases.extend(str(item) for item in value if item)
    aliases = [alias.strip().upper() for alias in aliases if alias.strip()]
    if sum(alias.startswith("CVE-") for alias in set(aliases)) > MAX_CVE_ALIASES:
        aliases = []
    own_id = str(row.get("id") or "").strip().upper()
    return [own_id, *aliases] if own_id else aliases


def group_rows(rows: Sequence[dict[str, Any]], field: str = "description") -> list[int]:
    """Return a group number for every row.

    Two rows are in the same group when they share the normalised text of
    ``field``, an identifier or an alias (transitively, via union-find).
    """
    parent = list(range(len(rows)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(first: int, second: int) -> None:
        root_first, root_second = find(first), find(second)
        if root_first != root_second:
            parent[max(root_first, root_second)] = min(root_first, root_second)

    first_row: dict[str, int] = {}
    for index, row in enumerate(rows):
        text = normalize_description(str(row.get(field) or ""))
        keys = [f"id:{key}" for key in _link_keys(row)]
        if text:
            keys.append(f"text:{text}")
        for key in keys:
            if key in first_row:
                union(first_row[key], index)
            else:
                first_row[key] = index

    return [find(index) for index in range(len(rows))]


def _bucket(seed: int, key: str) -> float:
    """Map a group key to a stable number in [0, 1)."""
    digest = hashlib.sha256(f"{seed}:{key}".encode()).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


def group_split_indices(
    rows: Sequence[dict[str, Any]],
    test_size: float = 0.1,
    validation_size: float = 0.0,
    seed: int = 42,
    field: str = "description",
) -> dict[str, list[int]]:
    """Assign whole groups of rows to train, validation and test.

    Returns the row indices of each split. The ``validation`` key is only
    present when ``validation_size`` is greater than zero.
    """
    if test_size <= 0 or validation_size < 0 or test_size + validation_size >= 1:
        raise ValueError("Need 0 < test_size and test_size + validation_size < 1.")

    groups = group_rows(rows, field=field)
    group_key: dict[int, str] = {}
    for index, group in enumerate(groups):
        key = str(rows[index].get("id") or index).upper()
        if group not in group_key or key < group_key[group]:
            group_key[group] = key

    splits: dict[str, list[int]] = {"train": [], "test": []}
    if validation_size > 0:
        splits["validation"] = []
    for index, group in enumerate(groups):
        value = _bucket(seed, group_key[group])
        if value < test_size:
            splits["test"].append(index)
        elif value < test_size + validation_size:
            splits["validation"].append(index)
        else:
            splits["train"].append(index)
    return splits
