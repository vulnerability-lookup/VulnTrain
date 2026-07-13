# CWE mapping generation tools

One-off scripts used to build the CWE mapping files. They are not part of the
installed `vulntrain` package and are only needed when the CWE data must be
regenerated.

## Pipeline

```
vulnerability.circl.lu.json          # raw CWE export from https://vulnerability.circl.lu
        │
        ▼  python tools/cwe/mapping_child_parent_cwe.py
parent_to_children_mapping.json      # parent CWE → direct children
        │
        ▼  python tools/cwe/hierarchy.py
cwe_hierarchy.json                   # CWEs grouped by hierarchy depth level
```

## Files

| File | Role |
|------|------|
| `vulnerability.circl.lu.json` | Raw CWE data snapshot (input). |
| `mapping_child_parent_cwe.py` | Builds `parent_to_children_mapping.json` from the raw snapshot. |
| `parent_to_children_mapping.json` | Generated: parent → children mapping. |
| `hierarchy.py` | Builds `cwe_hierarchy.json` (hierarchy levels) from the parent/children mapping. |
| `cwe_hierarchy.json` | Generated: CWE IDs grouped by depth level. |

The mapping consumed at training time by
`vulntrain-train-cwe-classification` lives in
`vulntrain/data/deep_child_to_ancestor.json` (CWE child → top ancestor); it is
maintained by hand and shipped with the package.
