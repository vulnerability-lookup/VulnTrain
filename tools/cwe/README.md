# CWE mapping generation tools

Scripts used to build the CWE mapping consumed by
`vulntrain-train-cwe-classification`. They are not part of the installed
`vulntrain` package.

Running them is **optional**: the resulting
`vulntrain/data/deep_child_to_ancestor.json` is versioned and shipped with
VulnTrain, so training works out of the box. Run the pipeline below before
training only when you want to pick up the latest CWE data (new CWEs, changed
mapping usages) from Vulnerability-Lookup, and commit the regenerated files.
Both steps are needed, in order: the first only refreshes the knowledge base,
the second regenerates the mapping the trainer reads.

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
