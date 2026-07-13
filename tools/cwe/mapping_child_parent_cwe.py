import json
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).parent

with open(HERE / "vulnerability.circl.lu.json", "r") as file:
    data = json.load(file)

parent_to_children = defaultdict(list)

for weakness in data.get("data", []):
    child_id = weakness.get("@ID")
    related = weakness.get("Related_Weaknesses", {}).get("Related_Weakness")

    if not related:
        continue

    if isinstance(related, dict):
        related = [related]

    for rel in related:
        if rel.get("@Nature") == "ChildOf":
            parent_id = rel.get("@CWE_ID")
            if parent_id and child_id:
                parent_to_children[parent_id].append(child_id)

with open(HERE / "parent_to_children_mapping.json", "w") as f:
    json.dump(parent_to_children, f, indent=2)
