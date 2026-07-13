"""Build the child-to-ancestor CWE mapping used by the CWE classifier.

Regenerates ``vulntrain/data/deep_child_to_ancestor.json`` from the knowledge
base produced by ``update_cwe_knowledge_base.py``. Each CWE is mapped to its
highest ancestor whose MITRE mapping usage is *Allowed* or
*Allowed-with-Review*, so the classifier is never trained to predict a
Discouraged or Prohibited CWE (e.g. the Pillars CWE-664, CWE-707...).
See https://github.com/vulnerability-lookup/VulnTrain/issues/17

CWEs with no allowed entry anywhere on their ancestor path are left out of
the mapping: the trainer then drops the corresponding training examples.
"""

import json
from pathlib import Path

ALLOWED_USAGES = {"Allowed", "Allowed-with-Review"}

HERE = Path(__file__).parent
OUTPUT = HERE.parent.parent / "vulntrain" / "data" / "deep_child_to_ancestor.json"


def primary_parent(record: dict) -> str | None:
    related = (record.get("Related_Weaknesses") or {}).get("Related_Weakness")
    if not related:
        return None
    if isinstance(related, dict):
        related = [related]
    child_of = [rel for rel in related if rel.get("@Nature") == "ChildOf"]
    if not child_of:
        return None
    for rel in child_of:
        if rel.get("@Ordinal") == "Primary":
            return rel.get("@CWE_ID")
    return child_of[0].get("@CWE_ID")


def main() -> None:
    with open(HERE / "vulnerability.circl.lu.json") as f:
        records = json.load(f)["data"]
    with open(HERE / "cwe_usage.json") as f:
        usage = json.load(f)

    parent = {
        record["@ID"]: primary_parent(record)
        for record in records
        if primary_parent(record)
    }

    def highest_allowed_ancestor(cwe_id: str) -> str | None:
        best = None
        node: str | None = cwe_id
        visited = set()
        while node and node not in visited:
            visited.add(node)
            if usage.get(node, {}).get("usage") in ALLOWED_USAGES:
                best = node
            node = parent.get(node)
        return best

    mapping = {}
    unmappable = []
    for record in records:
        cwe_id = record["@ID"]
        ancestor = highest_allowed_ancestor(cwe_id)
        if ancestor:
            mapping[cwe_id] = ancestor
        else:
            unmappable.append(cwe_id)

    with open(OUTPUT, "w") as f:
        json.dump(dict(sorted(mapping.items(), key=lambda kv: int(kv[0]))), f, indent=2)

    labels = sorted(set(mapping.values()), key=int)
    discouraged = [
        cwe for cwe in labels if usage.get(cwe, {}).get("usage") not in ALLOWED_USAGES
    ]
    print(f"{len(mapping)} CWEs mapped to {len(labels)} labels -> {OUTPUT}")
    print(f"Labels with non-allowed usage: {discouraged or 'none'}")
    if unmappable:
        print(
            f"{len(unmappable)} CWEs without any allowed ancestor "
            f"(excluded): {sorted(unmappable, key=int)}"
        )


if __name__ == "__main__":
    main()
