# CWE mapping generation tools

One-off scripts used to build the CWE mapping files. They are not part of the
installed `vulntrain` package and are only needed when the CWE data must be
regenerated.

## Pipeline

```
python tools/cwe/update_cwe_knowledge_base.py   # fetches from the Vulnerability-Lookup API
        │
        ├── vulnerability.circl.lu.json      # raw CWE records
        └── cwe_usage.json                   # per-CWE mapping usage (Allowed, Discouraged, ...)
        │
        ▼  python tools/cwe/build_child_to_ancestor.py
vulntrain/data/deep_child_to_ancestor.json   # CWE → highest allowed ancestor (trainer input)
```

Each CWE is mapped to its highest ancestor whose MITRE mapping usage is
*Allowed* or *Allowed-with-Review*, so the CWE classifier is never trained to
predict a Discouraged or Prohibited CWE (issue #17). CWEs without any allowed
entry on their ancestor path (e.g. CWE-20, CWE-200) are excluded: the trainer
drops the corresponding examples.

## Files

| File | Role |
|------|------|
| `update_cwe_knowledge_base.py` | Refreshes the knowledge base from `https://vulnerability.circl.lu/api/cwe/`. |
| `vulnerability.circl.lu.json` | Generated: raw CWE data snapshot. |
| `cwe_usage.json` | Generated: per-CWE name, abstraction, and mapping usage. |
| `build_child_to_ancestor.py` | Builds `vulntrain/data/deep_child_to_ancestor.json` (shipped with the package, consumed by `vulntrain-train-cwe-classification`). |
| `mapping_child_parent_cwe.py` | Builds `parent_to_children_mapping.json` from the raw snapshot. |
| `parent_to_children_mapping.json` | Generated: parent → children mapping. |
| `hierarchy.py` | Builds `cwe_hierarchy.json` (hierarchy levels) from the parent/children mapping. |
| `cwe_hierarchy.json` | Generated: CWE IDs grouped by depth level. |
