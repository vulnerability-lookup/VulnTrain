import argparse
import logging
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

import evaluate
import numpy as np
import torch
from codecarbon import EmissionsTracker
from datasets import Dataset, DatasetDict, concatenate_datasets, load_dataset
from sklearn.metrics import classification_report, f1_score
from sklearn.utils.class_weight import compute_class_weight
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    Trainer,
    TrainingArguments,
)

from vulntrain.trainers.classify_severity_cnvd import (
    FocalLossTrainer,
    WeightedTrainer,
    deduplicate_split,
)
from vulntrain.utils import clamp_tokenizer_max_length, push_emissions_report

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SEVERITY_MAPPING = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
ID2LABEL = {v: k for k, v in SEVERITY_MAPPING.items()}


def compute_metrics(eval_pred):
    """Compute accuracy and per-class precision/recall/F1."""
    accuracy = evaluate.load("accuracy")
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=-1)

    acc = accuracy.compute(predictions=predictions, references=labels)
    macro_f1 = f1_score(labels, predictions, average="macro", zero_division=0)

    report = classification_report(
        labels,
        predictions,
        labels=list(range(len(SEVERITY_MAPPING))),
        target_names=[ID2LABEL[i] for i in range(len(SEVERITY_MAPPING))],
        output_dict=True,
        zero_division=0,
    )

    metrics = {**acc, "f1_macro": macro_f1}
    for label_name in SEVERITY_MAPPING:
        if label_name in report:
            metrics[f"{label_name}_precision"] = report[label_name]["precision"]
            metrics[f"{label_name}_recall"] = report[label_name]["recall"]
            metrics[f"{label_name}_f1"] = report[label_name]["f1-score"]

    return metrics


def score_to_severity(score: float, v2_thresholds: bool = False) -> str:
    """Map a CVSS score to a severity label.

    CVSS v2 has no Critical rating: with ``v2_thresholds`` every score of 7.0
    or more is High.
    """
    if score >= 9.0 and not v2_thresholds:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def build_text(example: dict[str, Any]) -> str:
    """Build the model input from the title, summary and risks of a bulletin."""
    parts = [example["title"].strip(), example["description"].strip()]
    if example["risks"]:
        parts.append("Risques : " + ", ".join(example["risks"]) + ".")
    return "\n".join(part for part in parts if part)


def prepare_dataset(
    dataset: Dataset, score_field: str = "cvss_max", cvss_v2: str = "exclude"
) -> Dataset:
    """Filter CERT-FR bulletins, then add the ``text`` and ``severity_label`` columns.

    ``cvss_v2`` sets how bulletins scored only with CVSS v2 (``v2_only``) are
    handled: ``exclude`` drops them, ``v2-thresholds`` labels them with the
    CVSS v2 ratings (no Critical) and ``v3-thresholds`` treats them like the
    other bulletins.
    """
    dataset = dataset.filter(lambda ex: ex[score_field] is not None)
    if cvss_v2 == "exclude":
        dataset = dataset.filter(lambda ex: not ex["v2_only"])

    def add_columns(example: dict[str, Any]) -> dict[str, Any]:
        v2_thresholds = cvss_v2 == "v2-thresholds" and example["v2_only"]
        return {
            "text": build_text(example),
            "severity_label": score_to_severity(example[score_field], v2_thresholds),
        }

    return dataset.map(add_columns)


def train(
    base_model,
    dataset_id,
    repo_id,
    model_save_dir="./vulnerability-classify",
    class_weights_mode="none",
    score_field="cvss_max",
    cvss_v2="exclude",
    num_epochs=5,
    learning_rate=3e-5,
    batch_size=16,
    max_length=512,
    push=True,
    push_card=True,
):
    dataset = load_dataset(dataset_id)

    if isinstance(dataset, DatasetDict):
        # Recombine pre-split dataset so we can re-split without leakage
        combined = concatenate_datasets(
            [dataset[split] for split in dataset if len(dataset[split]) > 0]
        )
    else:
        combined = dataset

    combined = prepare_dataset(combined, score_field=score_field, cvss_v2=cvss_v2)

    if len(combined) == 0:
        raise ValueError(
            "No data left after filtering. Please check the dataset and label mapping."
        )

    # CERT-FR summaries are often boilerplate: split on the input text so
    # identical texts never end up in both train and test.
    dataset = deduplicate_split(combined, test_size=0.2, seed=42, field="text")

    label_counter = Counter(dataset["train"]["severity_label"])
    logger.info(f"Label distribution after filtering: {label_counter}")

    # Compute class weights for the training set
    class_weights = None
    if class_weights_mode in ("sqrt", "balanced", "focal"):
        all_labels = np.array(
            [SEVERITY_MAPPING[label] for label in dataset["train"]["severity_label"]]
        )
        present_classes = np.unique(all_labels)
        weights = compute_class_weight(
            class_weight="balanced", classes=present_classes, y=all_labels
        )
        class_weights_array = np.ones(len(SEVERITY_MAPPING), dtype=np.float32)
        for cls, w in zip(present_classes, weights):
            if class_weights_mode == "sqrt":
                class_weights_array[cls] = np.sqrt(w)
            else:
                class_weights_array[cls] = w
        class_weights = torch.tensor(class_weights_array, dtype=torch.float)
        logger.info(
            f"Class weights ({class_weights_mode}): "
            f"{dict(zip(SEVERITY_MAPPING.keys(), class_weights_array))}"
        )
    else:
        logger.info("Class weights: disabled (uniform loss)")

    tokenizer = AutoTokenizer.from_pretrained(base_model)
    clamp_tokenizer_max_length(tokenizer, base_model)
    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    def tokenize_function(examples):
        tokenized = tokenizer(
            examples["text"],
            truncation=True,
            max_length=max_length,
        )
        tokenized["labels"] = [
            SEVERITY_MAPPING[label] for label in examples["severity_label"]
        ]
        return tokenized

    tokenized_datasets = dataset.map(
        tokenize_function,
        batched=True,
        remove_columns=dataset["train"].column_names,
    )

    model = AutoModelForSequenceClassification.from_pretrained(
        base_model,
        num_labels=len(SEVERITY_MAPPING),
        id2label=ID2LABEL,
        label2id=SEVERITY_MAPPING,
    )

    training_args = TrainingArguments(
        output_dir=model_save_dir,
        eval_strategy="epoch",
        save_strategy="epoch",
        learning_rate=learning_rate,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size,
        num_train_epochs=num_epochs,
        weight_decay=0.01,
        logging_steps=10,
        save_total_limit=3,
        load_best_model_at_end=True,
        # Macro F1 rather than accuracy: the classes are imbalanced
        metric_for_best_model="f1_macro",
        greater_is_better=True,
        hub_model_id=repo_id,
    )

    trainer_kwargs = dict(
        model=model,
        args=training_args,
        train_dataset=tokenized_datasets["train"],
        eval_dataset=tokenized_datasets["test"],
        data_collator=data_collator,
        compute_metrics=compute_metrics,
    )

    if class_weights_mode == "focal":
        trainer = FocalLossTrainer(**trainer_kwargs, gamma=2.0, alpha=class_weights)
    elif class_weights is not None:
        trainer = WeightedTrainer(**trainer_kwargs, class_weights=class_weights)
    else:
        trainer = Trainer(**trainer_kwargs)

    # Save emissions data inside the model directory so it gets pushed to the
    # Hub together with the model.
    tracker = EmissionsTracker(
        project_name="VulnTrain",
        output_dir=model_save_dir,
        output_file="emissions.csv",
        allow_multiple_runs=True,
    )
    tracker.start()
    try:
        trainer.train()
    finally:
        tracker.stop()
        model.save_pretrained(model_save_dir)
        tokenizer.save_pretrained(model_save_dir)

    eval_results = trainer.evaluate()
    logger.info(f"Evaluation results: {eval_results}")

    if not push:
        return

    trainer.push_to_hub()
    tokenizer.push_to_hub(repo_id)

    if push_emissions_report(model_save_dir, repo_id):
        logger.info(f"Emissions report pushed to {repo_id}")

    if not push_card:
        return

    # Generate and push model card with actual eval metrics
    test_labels = [SEVERITY_MAPPING[label] for label in dataset["test"]["severity_label"]]
    test_samples = len(test_labels)
    label_counts = Counter(test_labels)

    loss_descriptions = {
        "none": "uniform cross-entropy (no class weighting)",
        "sqrt": "class-weighted cross-entropy (sqrt-dampened)",
        "balanced": "class-weighted cross-entropy (balanced)",
        "focal": "focal loss (gamma=2.0, balanced alpha)",
    }
    cvss_v2_descriptions = {
        "exclude": "bulletins scored only with CVSS v2 are excluded",
        "v2-thresholds": "bulletins scored only with CVSS v2 are labelled with the CVSS v2 ratings (no Critical)",
        "v3-thresholds": "bulletins scored only with CVSS v2 are labelled with the CVSS v3 thresholds",
    }

    template_vars = {
        "base_model": base_model,
        "dataset_id": dataset_id,
        "repo_id": repo_id,
        "test_samples": f"{test_samples:,}",
        "accuracy": eval_results.get("eval_accuracy", 0),
        "f1_macro": eval_results.get("eval_f1_macro", 0),
        "score_field": score_field,
        "cvss_v2_description": cvss_v2_descriptions[cvss_v2],
        "loss_description": loss_descriptions.get(class_weights_mode, "uniform cross-entropy"),
        "learning_rate": training_args.learning_rate,
        "batch_size": training_args.per_device_train_batch_size,
        "num_epochs": int(training_args.num_train_epochs),
    }

    for label_name, label_id in SEVERITY_MAPPING.items():
        count = label_counts.get(label_id, 0)
        template_vars[f"{label_name}_precision"] = eval_results.get(f"eval_{label_name}_precision", 0)
        template_vars[f"{label_name}_recall"] = eval_results.get(f"eval_{label_name}_recall", 0)
        template_vars[f"{label_name}_f1"] = eval_results.get(f"eval_{label_name}_f1", 0)
        template_vars[f"{label_name}_support"] = f"{count:,}"
        template_vars[f"{label_name}_pct"] = 100 * count / test_samples if test_samples else 0

    model_card_template = Path(__file__).parent.parent / "cards" / "model_card_certfr_severity.md"
    if model_card_template.exists():
        from huggingface_hub import HfApi

        card_content = model_card_template.read_text().format(**template_vars)
        card_path = Path(model_save_dir) / "README.md"
        card_path.write_text(card_content)

        api = HfApi()
        api.upload_file(
            path_or_fileobj=str(card_path),
            path_in_repo="README.md",
            repo_id=repo_id,
            commit_message="Update model card with evaluation metrics",
        )
        logger.info(f"Model card pushed to {repo_id}")


def main():
    parser = argparse.ArgumentParser(
        description="Train a vulnerability severity classification model on French CERT-FR bulletins."
    )
    parser.add_argument(
        "--base-model",
        dest="base_model",
        default="almanach/camembertv2-base",
        help="Base model to use (e.g. almanach/camembertv2-base, almanach/camembert-base, FacebookAI/xlm-roberta-base).",
    )
    parser.add_argument(
        "--dataset-id",
        dest="dataset_id",
        default="CIRCL/Vulnerability-CERT-FR",
        help="Path of the dataset. Local or Hugging Face Hub.",
    )
    parser.add_argument(
        "--repo-id",
        dest="repo_id",
        required=True,
        help="Repository name to push the model to (include org if needed).",
    )
    parser.add_argument(
        "--model-save-dir",
        dest="model_save_dir",
        default="results",
        help="Directory to save tokenizer and model.",
    )
    parser.add_argument(
        "--score",
        dest="score_field",
        default="cvss_max",
        choices=["cvss_max", "cvss_mean"],
        help="Bulletin score used as label: highest (default) or mean CVSS score of the referenced CVEs.",
    )
    parser.add_argument(
        "--cvss-v2",
        dest="cvss_v2",
        default="exclude",
        choices=["exclude", "v2-thresholds", "v3-thresholds"],
        help="Handling of bulletins scored only with CVSS v2: exclude them (default), label them with the CVSS v2 ratings (no Critical), or with the CVSS v3 thresholds.",
    )
    parser.add_argument(
        "--class-weights",
        dest="class_weights_mode",
        default="none",
        choices=["none", "sqrt", "balanced", "focal"],
        help="Class weighting mode: none (uniform loss), sqrt (dampened), balanced (full inverse-frequency), focal (focal loss with alpha weights).",
    )
    parser.add_argument("--epochs", type=int, default=5, help="Number of training epochs.")
    parser.add_argument(
        "--learning-rate", dest="learning_rate", type=float, default=3e-5, help="Learning rate."
    )
    parser.add_argument(
        "--batch-size", dest="batch_size", type=int, default=16, help="Per-device batch size."
    )
    parser.add_argument(
        "--max-length", dest="max_length", type=int, default=512, help="Maximum input length in tokens."
    )
    parser.add_argument(
        "--no-push",
        dest="no_push",
        action="store_true",
        default=False,
        help="Train and evaluate locally without pushing to Hugging Face Hub.",
    )
    parser.add_argument(
        "--no-card",
        dest="no_card",
        action="store_true",
        default=False,
        help="Skip pushing the model card to Hugging Face Hub.",
    )

    args = parser.parse_args()

    dir_path = Path(args.model_save_dir)
    if dir_path.exists() and dir_path.is_dir():
        shutil.rmtree(dir_path)

    logger.info(f"Using base model: {args.base_model}")
    logger.info(f"Dataset ID: {args.dataset_id}")
    logger.info(f"Repo ID: {args.repo_id}")
    logger.info(f"Saving model to: {args.model_save_dir}")
    logger.info("Starting the training process…")

    train(
        args.base_model,
        args.dataset_id,
        args.repo_id,
        args.model_save_dir,
        class_weights_mode=args.class_weights_mode,
        score_field=args.score_field,
        cvss_v2=args.cvss_v2,
        num_epochs=args.epochs,
        learning_rate=args.learning_rate,
        batch_size=args.batch_size,
        max_length=args.max_length,
        push=not args.no_push,
        push_card=not args.no_card,
    )


if __name__ == "__main__":
    main()
