# ATT&CK dataset maintenance scripts

One-off scripts for maintaining the published
[`CIRCL/vulnerability-attack-techniques`](https://huggingface.co/datasets/CIRCL/vulnerability-attack-techniques)
dataset, complementing the `vulntrain-dataset-attack-generation` entry
point.

## The `cwes_predicted` column

The dataset generator produces every column **except** `cwes_predicted`
(the top-1 parent-level prediction of
[`CIRCL/cwe-parent-vulnerability-classification-roberta-base`](https://huggingface.co/CIRCL/cwe-parent-vulnerability-classification-roberta-base)
per row, formatted like the gold `cwes` display strings). The column is
what the trainer's `--metadata cwe_predicted` cascade arm consumes, so
it must be refreshed:

- after every dataset regeneration (`vulntrain-dataset-attack-generation
  --push` drops it), and
- whenever the CWE classifier is retrained (the predictions, and the
  agreement number below, change with it).

Two steps, from this directory:

```bash
python3 predict_cwes.py                      # writes cwe_predictions.json
python3 update_dataset_cwes_predicted.py     # verifies + pushes the column
```

`predict_cwes.py` runs the CWE model over all ~1,200 rows (a few minutes
on CPU, seconds on GPU) and prints the top-1 exact-id agreement with the
gold `cwes` column — 27.3% at the time of dataset v2.1. The update
script asserts full row coverage and byte-identical original columns
before pushing; use `--no-push` for a dry run.

CWE display names come from the knowledge base maintained in
`tools/cwe/` (`vulnerability.circl.lu.json`); refresh it first if it is
stale (see `tools/cwe/README.md`).
