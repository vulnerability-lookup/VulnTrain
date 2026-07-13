# CWE Classifier: Improvements Report

Technical report on changes made to the CWE classification pipeline (dataset
generation, CWE knowledge base, and `cwe_guesser_patches.py` trainer) following
the analysis in [VulnTrain#17](https://github.com/vulnerability-lookup/VulnTrain/issues/17).

## Context

An external review of the CWE suggestions surfaced through VLAgentIc noted
that most suggested CWEs were **Discouraged** for mapping by MITRE (CWE-703,
CWE-707, CWE-284, ...) while obvious, *Allowed* candidates (such as CWE-620
for an unverified password change) were missed.

The root cause was in the training labels: the trainer mapped every CWE of the
dataset to its deepest ancestor via `deep_child_to_ancestor.json`, and those
deep ancestors are mostly Pillars and high-level Classes — exactly the entries
MITRE marks as Discouraged. The model could only ever predict discouraged
CWEs.

## Changes

### Label set restricted to allowed CWEs

The CWE knowledge base is now refreshed from the
[Vulnerability-Lookup](https://vulnerability.circl.lu) API by
`tools/cwe/update_cwe_knowledge_base.py`, which stores each CWE's
`Mapping_Notes` usage (*Allowed*, *Allowed-with-Review*, *Discouraged*,
*Prohibited*) in `tools/cwe/cwe_usage.json`. As of July 2026: 749 Allowed,
93 Allowed-with-Review, 44 Discouraged, 83 Prohibited.

`tools/cwe/build_child_to_ancestor.py` then regenerates
`vulntrain/data/deep_child_to_ancestor.json`: each CWE is mapped to its
**highest ancestor whose usage is Allowed or Allowed-with-Review**. The label
set went from 26 discouraged deep ancestors to 303 allowed CWEs. Since a
classifier can only predict labels it was trained on, the model structurally
cannot suggest a Discouraged or Prohibited CWE anymore.

90 CWEs have no allowed entry anywhere on their ancestor path (including
common ones like CWE-20, CWE-200, CWE-287, CWE-400 — this is MITRE's actual
guidance). Examples carrying only such CWEs are excluded from training rather
than being mapped to a discouraged label.

### Dataset generation fixes

Two bugs in `vulntrain/datasets/cwe-guesser-dataset.py` reduced the quantity
and quality of the training data:

- **Stale CWE labels (cvelistv5):** the `cwe` variable was only assigned when
  a record had `problemTypes` descriptions, so records without them silently
  inherited the CWE of the previously processed vulnerability. Each record now
  gets a fresh list, all `problemTypes` descriptions are collected (not just
  the first of the first), and the structured `cweId` is preferred over the
  free-text description.
- **GHSA examples silently dropped:** GHSA records stored their CWEs in a
  separate `cwes` column while the trainer only reads `cwe`, so no GHSA
  example ever contributed to training. Both sources now emit a `cwe` column
  as a list of strings.

Because the `cwe` column type changed, the
[CIRCL/vulnerability-cwe-patch](https://huggingface.co/datasets/CIRCL/vulnerability-cwe-patch)
dataset must be rebuilt once with the new `--from-scratch` flag:

```bash
python vulntrain/datasets/cwe-guesser-dataset.py --sources cvelistv5,github,pysec,csaf_redhat --repo-id=CIRCL/vulnerability-cwe-patch --from-scratch
```

(The flag was added together with a fix to the incremental push: the previous
concatenation call used a non-existent `Dataset.concatenate` method, whose
`AttributeError` was silently swallowed — appends actually replaced the
dataset.)

### Top-k accuracy metrics

The model is consumed as a *suggester* of candidate CWEs, so whether the right
CWE appears among the top suggestions matters more than exact top-1 accuracy —
especially with 303 fine-grained classes. `compute_metrics` now reports
`accuracy_top3` and `accuracy_top5` alongside accuracy and macro F1, and the
best checkpoint is selected by `f1_macro` instead of eval loss
(`metric_for_best_model`).

### Long-context input and ModernBERT

The input is a vulnerability description plus commit messages and diffs, but
only the first patch was used and everything was truncated at 512 tokens
(roberta-base's limit), so most of the patch content was never seen by the
model. Changes:

- all patches of a record are concatenated into the input text;
- the tokenizer truncation length defaults to the model's maximum input
  length (capped at 8192), overridable with `--max-length`;
- padding is now dynamic per batch (`DataCollatorWithPadding`) instead of
  padding everything to the maximum length.

This makes [ModernBERT-base](https://huggingface.co/answerdotai/ModernBERT-base)
(8192-token context, code-aware pretraining) the recommended base model:

```bash
vulntrain-train-cwe-classification --base-model answerdotai/ModernBERT-base --dataset-id CIRCL/vulnerability-cwe-patch --repo-id CIRCL/vulnerability-cwe-classification-modernbert-base --batch-size 8
```

Lower the batch size compared to roberta-base: sequences are up to 16× longer.

### Class weighting strategies

With 303 heavily imbalanced classes, fully *balanced* class weights (the
previous hard-coded behaviour) over-boost classes with a handful of examples.
The `--class-weights` flag from the CNVD severity trainer was ported:
`none` (uniform loss), `sqrt` (sqrt-dampened weights), `balanced` (previous
behaviour, still the default) and `focal` (focal loss, gamma=2.0, balanced
alpha). Worth comparing `sqrt` and `focal` against the `balanced` baseline.

## Baseline to beat

First model trained with the allowed-only label set (roberta-base, 40 epochs,
balanced weights, 512-token context, before the dataset regeneration):

| Metric | Value |
|--------|-------|
| Accuracy | 0.5683 |
| F1 macro | 0.2101 |
| Labels | 303 |
| Train examples | 6,460 |

The accuracy/F1-macro gap shows the long tail of rare CWEs is barely learned.
Expected levers, in order: dataset regeneration (recovers all GHSA examples
and fixes mislabeled cvelistv5 rows), long-context ModernBERT (sees the full
patches), then class-weighting experiments.

## Possible future work

- **Multi-label training:** records often carry several CWEs; the trainer
  currently keeps only the first mappable one. Sigmoid multi-label targets
  would use all of them and match reality (a vulnerability can legitimately
  be CWE-620 *and* CWE-640).
- **Minimum label support:** collapse labels with fewer than ~5 training
  examples out of the label set instead of teaching the model classes it
  cannot learn.
- **Hierarchy-aware evaluation:** report a soft accuracy where predicting an
  ancestor or descendant of the reference CWE counts as partially correct.
