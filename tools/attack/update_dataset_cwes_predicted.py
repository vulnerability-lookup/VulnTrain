"""Refresh the `cwes_predicted` column of the ATT&CK techniques dataset.

Joins cwe_predictions.json (produced by predict_cwes.py: top-1 prediction
of CIRCL/cwe-parent-vulnerability-classification-roberta-base per row)
onto CIRCL/vulnerability-attack-techniques and pushes the result. All
other columns are verified unchanged before the push.

Run this after every dataset regeneration (the generator does not produce
the column) and whenever the CWE classifier is retrained — see README.md
in this directory.

Usage: python3 update_dataset_cwes_predicted.py [--predictions FILE] [--no-push]
"""

import argparse
import json

from datasets import load_dataset

DATASET_ID = "CIRCL/vulnerability-attack-techniques"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--predictions", default="cwe_predictions.json")
    parser.add_argument("--no-push", action="store_true")
    args = parser.parse_args()

    predictions = json.load(open(args.predictions))
    dataset = load_dataset(DATASET_ID)

    missing = [
        row["id"] for split in dataset for row in dataset[split]
        if row["id"] not in predictions
    ]
    assert not missing, f"{len(missing)} rows without prediction: {missing[:5]}"

    updated = dataset.map(
        lambda row: {"cwes_predicted": predictions[row["id"]]}
    )

    for split in dataset:
        assert len(updated[split]) == len(dataset[split])
        old_cols = set(dataset[split].column_names) - {"cwes_predicted"}
        assert set(updated[split].column_names) == old_cols | {"cwes_predicted"}
        for old, new in zip(dataset[split], updated[split]):
            assert all(new[c] == old[c] for c in old_cols), old["id"]
    print("verified: all original columns byte-identical, all rows covered")

    example = updated["test"][0]
    print(f"sample: {example['id']} gold={example['cwes']} "
          f"predicted={example['cwes_predicted']}")

    if args.no_push:
        print("--no-push: stopping before Hub upload")
        return
    updated.push_to_hub(
        DATASET_ID,
        commit_message="refresh cwes_predicted (top-1 of "
        "CIRCL/cwe-parent-vulnerability-classification-roberta-base)",
    )
    print("pushed")


if __name__ == "__main__":
    main()
