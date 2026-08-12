"""Predict a CWE for every row of the ATT&CK techniques dataset.

Runs CIRCL/cwe-parent-vulnerability-classification-roberta-base (the
deployed VLAI CWE guesser, parent-level, 303 classes) over each row's
title+description and writes {cve_id: ["CWE-<id> <name>"]} to
cwe_predictions.json, formatted like the dataset's gold `cwes` strings
so the trainer's `--metadata cwe_predicted` arm verbalizes identically
to the gold arm ("CWE: ..."), isolating signal quality as the only
difference.

Also reports top-1 agreement with the gold `cwes` column (exact id match
after parsing "CWE-<id>" prefixes; gold rows with free-text-only labels
are excluded from the denominator).

Part of the `cwes_predicted` column refresh pipeline — see README.md in
this directory.

Usage: python3 predict_cwes.py [--out FILE]
"""

import argparse
import json
import re
from pathlib import Path

import torch
from datasets import load_dataset
from transformers import AutoModelForSequenceClassification, AutoTokenizer

MODEL_ID = "CIRCL/cwe-parent-vulnerability-classification-roberta-base"
DATASET_ID = "CIRCL/vulnerability-attack-techniques"
REPO_ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--cwe-knowledge-base",
        default=str(REPO_ROOT / "tools/cwe/vulnerability.circl.lu.json"),
        help="CWE id->name knowledge base (see tools/cwe/README.md).",
    )
    parser.add_argument("--out", default="cwe_predictions.json")
    parser.add_argument("--batch-size", type=int, default=16)
    args = parser.parse_args()

    kb = json.load(open(args.cwe_knowledge_base))
    names = {entry["@ID"]: entry["@Name"] for entry in kb["data"]}

    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID)
    model.eval()
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model.to(device)

    dataset = load_dataset(DATASET_ID)
    rows = [row for split in dataset for row in dataset[split]]
    texts = [
        f"{row.get('title') or ''}\n{row.get('description') or ''}".strip()
        for row in rows
    ]

    predictions: dict[str, list[str]] = {}
    for start in range(0, len(texts), args.batch_size):
        batch = tokenizer(
            texts[start : start + args.batch_size],
            padding=True,
            truncation=True,
            max_length=512,
            return_tensors="pt",
        ).to(device)
        with torch.no_grad():
            logits = model(**batch).logits
        for offset, label_id in enumerate(logits.argmax(dim=1).tolist()):
            cwe_id = model.config.id2label[label_id]
            name = names.get(cwe_id, "")
            display = f"CWE-{cwe_id} {name}".strip()
            predictions[rows[start + offset]["id"]] = [display]

    # Top-1 agreement with gold, where gold has a parseable CWE id.
    agree = total = 0
    for row in rows:
        gold_ids = {
            match.group(1)
            for cwe in row.get("cwes") or []
            for match in [re.match(r"CWE-(\d+)", cwe)]
            if match
        }
        if not gold_ids:
            continue
        total += 1
        predicted_id = predictions[row["id"]][0].split()[0].removeprefix("CWE-")
        agree += predicted_id in gold_ids
    print(f"rows: {len(rows)}, gold rows with parseable CWE id: {total}")
    print(f"top-1 exact-id agreement with gold: {agree}/{total} = {agree/total:.3f}")

    json.dump(predictions, open(args.out, "w"), indent=0, sort_keys=True)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
