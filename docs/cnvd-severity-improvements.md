# CNVD Severity Classifier: Improvements Report

Technical report on changes made to the CNVD severity trainer (`classify_severity_cnvd.py`) following the independent analysis in [VulnTrain#19](https://github.com/vulnerability-lookup/VulnTrain/issues/19).

## Context

An external review of the [CIRCL/vulnerability-severity-classification-chinese-macbert-base](https://huggingface.co/CIRCL/vulnerability-severity-classification-chinese-macbert-base) model identified several issues: data leakage in the train/test split, poor Low-class recall, keyword dependency, and a suboptimal published checkpoint. The reported headline accuracy of 77.83% was inflated by ~1.7pp due to leakage.

## Changes

### Data leakage fix

**Problem:** CNVD reuses boilerplate descriptions across different vulnerability IDs. The original `train_test_split` split by row index, allowing 1,587 identical descriptions (15.6% of the test set) to appear in both splits.

**Fix:** New `deduplicate_split()` function groups all entries by description text and assigns entire groups to one split. No description appears in both train and test.

**Impact:** The old model evaluated on the deduplicated test set scores 85.2% (inflated — it was trained on data overlapping this test set). A model retrained on the deduplicated split scores 76.8%, matching the independently measured unleaked accuracy of 76.6%.

### Class weighting experiments

**Problem:** The Low class (~9% of data) had only ~41% recall on unleaked data, with 60% of Low entries misclassified as Medium.

Four loss strategies were tested on the deduplicated split:

| Mode | Low recall | Medium recall | High recall | Overall acc |
|------|-----------|---------------|-------------|-------------|
| Uniform (none) | 0.4099 | 0.8165 | 0.7809 | 0.7677 |
| Sqrt-dampened | 0.4902 | 0.7481 | 0.8056 | 0.7457 |
| Balanced | 0.6084 | 0.7024 | 0.8099 | 0.7323 |
| Focal (gamma=2) | 0.6328 | 0.6441 | 0.8349 | 0.7110 |

**Conclusion:** Every weighting strategy that improved Low recall caused disproportionate Medium recall loss. The Low/Medium vocabulary overlap in CNVD descriptions makes this a data-level limitation, not a loss-function problem. The trainer defaults to uniform loss.

A `--class-weights` flag (`none`, `sqrt`, `balanced`, `focal`) was added for future experimentation.

### Per-class metrics

`compute_metrics` now reports precision, recall, and F1 per class (Low/Medium/High) alongside overall accuracy and macro F1 at each evaluation epoch.

### Best model checkpoint selection

- `metric_for_best_model` set to `accuracy` (was defaulting to `eval_loss`)
- `save_total_limit` increased from 2 to 3 to prevent the best checkpoint from being pruned

### CodeCarbon tracker scoping

The `@track_emissions` decorator wrapped the entire `train()` function, including `push_to_hub()`. The codecarbon background thread never stopped during the upload. Replaced with an explicit `EmissionsTracker` start/stop scoped to `trainer.train()` only. Also removed `push_to_hub=True` from `TrainingArguments` (it caused `trainer.train()` to upload internally before returning). The same fix was applied to `classify_severity.py`.

### Dynamic model card

The model card is now a template (`model_card_cnvd_severity.md`) populated with actual eval metrics from `trainer.evaluate()` after each training run. Documents per-class metrics, training configuration, and known limitations.

### Known limitations documented

- Low severity recall (~41%)
- Keyword dependency (accuracy drops from ~89% to ~55% on atypical-severity entries)
- Negation blindness
- CVE overlap (81% of CNVD entries have a CVE equivalent)

## Commits

| Commit | Description |
|--------|-------------|
| `6352273` | Data leakage fix, class-weighted loss, per-class metrics, best model selection |
| `b1679fb` | CNVD severity model comparison validator |
| `1fdee05` | Sqrt-dampened class weights |
| `a81f90d` | Scoped codecarbon tracker (CNVD trainer) |
| `65d3d88` | Removed push_to_hub from TrainingArguments |
| `b7a2d6d` | Scoped codecarbon tracker (severity trainer) |
| `ed2c230` | `--class-weights` flag (none/sqrt/balanced) |
| `f1cd426` | Focal loss option |
| `9fa0f86` | Default to uniform loss |
| `7920361` | Static model card |
| `5b2866c` | Dynamic model card from eval metrics |

## References

- Issue: [VulnTrain#19](https://github.com/vulnerability-lookup/VulnTrain/issues/19)
- Model: [CIRCL/vulnerability-severity-classification-chinese-macbert-base](https://huggingface.co/CIRCL/vulnerability-severity-classification-chinese-macbert-base)
- Dataset: [CIRCL/Vulnerability-CNVD](https://huggingface.co/datasets/CIRCL/Vulnerability-CNVD)
- External validation: [eromang/researches/CNVD-Dataset-Validation](https://github.com/eromang/researches/tree/main/CNVD-Dataset-Validation)
