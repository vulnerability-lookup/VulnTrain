import argparse

import numpy as np
import torch
from datasets import concatenate_datasets, load_dataset
from sklearn.metrics import classification_report, confusion_matrix
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from vulntrain.trainers.classify_severity_cnvd import (
    SEVERITY_MAPPING,
    deduplicate_split,
    map_cvss_to_severity,
)

ID2LABEL = {v: k for k, v in SEVERITY_MAPPING.items()}
LABEL2CHINESE = {"Low": "低", "Medium": "中", "High": "高"}


def run_model(model_name, texts, batch_size=64):
    """Run inference and return predicted label indices."""
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name)
    model.eval()

    all_preds = []
    for i in range(0, len(texts), batch_size):
        batch_texts = texts[i : i + batch_size]
        inputs = tokenizer(
            batch_texts, padding=True, truncation=True, max_length=512, return_tensors="pt"
        )
        with torch.no_grad():
            logits = model(**inputs).logits
        preds = torch.argmax(logits, dim=-1).tolist()
        all_preds.extend(preds)

    return np.array(all_preds)


def print_comparison(name, true_labels, preds, label_names):
    """Print classification report and confusion matrix for one model."""
    print(f"\n{'=' * 60}")
    print(f"  {name}")
    print(f"{'=' * 60}")
    print(
        classification_report(
            true_labels, preds, target_names=label_names, digits=4, zero_division=0
        )
    )
    print("Confusion matrix (rows=true, cols=predicted):")
    print(f"{'':>10}", "  ".join(f"{l:>8}" for l in label_names))
    cm = confusion_matrix(true_labels, preds, labels=list(range(len(label_names))))
    for i, row in enumerate(cm):
        print(f"{label_names[i]:>10}", "  ".join(f"{v:>8}" for v in row))
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Compare old and new CNVD severity classification models."
    )
    parser.add_argument(
        "--old-model",
        dest="old_model",
        default="CIRCL/vulnerability-severity-classification-chinese-macbert-base",
        help="Old model (before leakage fix / class weighting).",
    )
    parser.add_argument(
        "--new-model",
        dest="new_model",
        default="CIRCL/vulnerability-severity-classification-chinese-macbert-base-test",
        help="New model (after improvements).",
    )
    parser.add_argument(
        "--dataset-id",
        dest="dataset_id",
        default="CIRCL/Vulnerability-CNVD",
        help="HF dataset ID.",
    )
    parser.add_argument(
        "--batch-size",
        dest="batch_size",
        type=int,
        default=64,
        help="Inference batch size.",
    )

    args = parser.parse_args()

    # --- Load and prepare a fair (deduplicated) test set ---
    print("Loading dataset...")
    dataset = load_dataset(args.dataset_id)

    # Recombine splits and re-split with deduplication
    combined = concatenate_datasets(
        [dataset[split] for split in dataset if len(dataset[split]) > 0]
    )
    combined = combined.map(map_cvss_to_severity)
    combined = combined.filter(lambda x: x["severity"] in ["低", "中", "高"])

    splits = deduplicate_split(combined, test_size=0.2, seed=42)
    test_set = splits["test"]

    texts = test_set["description"]
    true_labels = np.array(
        [SEVERITY_MAPPING[label] for label in test_set["severity_label"]]
    )
    label_names = [ID2LABEL[i] for i in range(len(SEVERITY_MAPPING))]

    print(f"Test set: {len(texts)} samples")
    for name, idx in SEVERITY_MAPPING.items():
        count = int((true_labels == idx).sum())
        print(f"  {name}: {count} ({100 * count / len(true_labels):.1f}%)")

    # --- Run both models on the same deduplicated test set ---
    print(f"\nRunning old model: {args.old_model}")
    old_preds = run_model(args.old_model, texts, args.batch_size)

    print(f"Running new model: {args.new_model}")
    new_preds = run_model(args.new_model, texts, args.batch_size)

    # --- Print side-by-side results ---
    print_comparison(f"OLD: {args.old_model}", true_labels, old_preds, label_names)
    print_comparison(f"NEW: {args.new_model}", true_labels, new_preds, label_names)

    # --- Summary delta ---
    old_acc = np.mean(old_preds == true_labels)
    new_acc = np.mean(new_preds == true_labels)
    print("=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    print(f"  Overall accuracy:  old={old_acc:.4f}  new={new_acc:.4f}  delta={new_acc - old_acc:+.4f}")

    for name, idx in SEVERITY_MAPPING.items():
        mask = true_labels == idx
        if mask.sum() == 0:
            continue
        old_recall = np.mean(old_preds[mask] == idx)
        new_recall = np.mean(new_preds[mask] == idx)
        print(
            f"  {name:>7} recall:  old={old_recall:.4f}  new={new_recall:.4f}  delta={new_recall - old_recall:+.4f}"
        )
    print()


if __name__ == "__main__":
    main()
