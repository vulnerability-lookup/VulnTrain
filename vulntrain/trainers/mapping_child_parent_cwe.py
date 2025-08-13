import json

with open("vulntrain/trainers/cwe_list.json", "r") as f:
    raw = json.load(f)

child_to_parent = {}

for entry in raw.get("data", []):
    child_id = entry.get("@ID")
    related = entry.get("Related_Weaknesses")

    if not related:
        continuevulntrain/trainers/cwe-guesser-commit-mess.py

    related_items = related.get("Related_Weakness")
    if not related_items:
        continue

    # Convert to list if it's a single object
    if isinstance(related_items, dict):
        related_items = [related_items]

    # Look for ChildOf relationships
    parent_candidates = [rel for rel in related_items if rel.get("@Nature") == "ChildOf"]

    if not parent_candidates:
        continue

    # Prefer the one marked Primary
    primary = next((p for p in parent_candidates if p.get("@Ordinal") == "Primary"), None)
    chosen = primary or parent_candidates[0]

    parent_id = chosen.get("@CWE_ID")
    if parent_id:
        child_to_parent[child_id] = parent_id

# Save result to JSON file
with open("vulntrain/trainers/child_to_parent_mapping.json", "w") as f:
    json.dump(child_to_parent, f, indent=2)

print(f"{len(child_to_parent)} mappings written to vulntrain/trainers/child_to_parent_mapping.json")
