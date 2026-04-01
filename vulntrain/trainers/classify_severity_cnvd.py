import argparse
import logging
import shutil
from collections import Counter
from pathlib import Path

import evaluate
import numpy as np
import torch
from codecarbon import track_emissions
from datasets import Dataset, DatasetDict, load_dataset
from sklearn.metrics import classification_report, f1_score
from sklearn.utils.class_weight import compute_class_weight
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    Trainer,
    TrainingArguments,
)

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define severity label mapping
SEVERITY_MAPPING = {"Low": 0, "Medium": 1, "High": 2}


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


# Define severity mapping function
def map_cvss_to_severity(example):
    severity_label = example.get("severity", "").strip()

    if severity_label == "低":
        severity_label = "Low"
    elif severity_label == "中":
        severity_label = "Medium"
    elif severity_label == "高":
        severity_label = "High"
    else:
        severity_label = "Unknown"

    example["severity_label"] = severity_label
    return example


def flatten_description(example):
    desc = example["description"]
    # Si desc est une liste de strings, join en une seule string
    if isinstance(desc, list):
        if all(isinstance(el, str) for el in desc):
            example["description"] = " ".join(desc)
        else:
            # Si liste imbriquée plus complexe, convertis en string brute
            example["description"] = str(desc)
    return example


class WeightedTrainer(Trainer):
    """Trainer subclass that applies class-weighted cross-entropy loss."""

    def __init__(self, *args, class_weights=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.class_weights = class_weights

    def compute_loss(
        self, model, inputs, return_outputs=False, num_items_in_batch=None
    ):
        labels = inputs.get("labels")
        outputs = model(**inputs)
        logits = outputs.get("logits")
        loss_fct = torch.nn.CrossEntropyLoss(
            weight=self.class_weights.to(logits.device)
        )
        loss = loss_fct(logits, labels)
        return (loss, outputs) if return_outputs else loss


def deduplicate_split(dataset, test_size=0.2, seed=42):
    """Split dataset so that no description text appears in both train and test.

    Deduplicates on the description field: groups entries by their description,
    then splits the unique groups — ensuring all entries sharing a description
    land in the same split.
    """
    # Build mapping: unique description -> list of row indices
    desc_to_indices: dict[str, list[int]] = {}
    for idx, desc in enumerate(dataset["description"]):
        desc_to_indices.setdefault(desc, []).append(idx)

    unique_descs = list(desc_to_indices.keys())
    n_test = max(1, int(len(unique_descs) * test_size))

    rng = np.random.RandomState(seed)
    rng.shuffle(unique_descs)

    test_descs = set(unique_descs[:n_test])

    train_indices = []
    test_indices = []
    for desc, indices in desc_to_indices.items():
        if desc in test_descs:
            test_indices.extend(indices)
        else:
            train_indices.extend(indices)

    logger.info(
        f"Deduplicated split: {len(unique_descs)} unique descriptions, "
        f"{len(train_indices)} train rows, {len(test_indices)} test rows"
    )

    return DatasetDict(
        {
            "train": dataset.select(train_indices),
            "test": dataset.select(test_indices),
        }
    )


@track_emissions(project_name="VulnTrain", allow_multiple_runs=True)
def train(base_model, dataset_id, repo_id, model_save_dir="./vulnerability-classify"):
    dataset = load_dataset(dataset_id)

    if isinstance(dataset, DatasetDict) and "train" in dataset:
        # Recombine pre-split dataset so we can re-split without leakage
        from datasets import concatenate_datasets

        combined = concatenate_datasets(
            [dataset[split] for split in dataset if len(dataset[split]) > 0]
        )
    else:
        combined = dataset if isinstance(dataset, Dataset) else dataset["train"]

    combined = combined.map(map_cvss_to_severity)
    combined = combined.filter(lambda x: x["severity"] in ["低", "中", "高"])

    if len(combined) == 0:
        raise ValueError(
            "No data left after filtering. Please check the dataset and label mapping."
        )

    # Split with deduplication on description to prevent data leakage
    dataset = deduplicate_split(combined, test_size=0.2, seed=42)

    label_counter = Counter([ex["severity_label"] for ex in dataset["train"]])
    logger.info(f"Label distribution after filtering: {label_counter}")

    # Compute dampened class weights for the training set.
    # Full "balanced" weights are too aggressive (Low gets ~6x Medium), causing
    # massive Medium recall loss. Square-root dampening provides a gentler boost
    # to the minority Low class without overwhelming Medium/High.
    all_labels = np.array(
        [SEVERITY_MAPPING[ex["severity_label"]] for ex in dataset["train"]]
    )
    present_classes = np.unique(all_labels)
    weights = compute_class_weight(
        class_weight="balanced", classes=present_classes, y=all_labels
    )
    class_weights_array = np.ones(len(SEVERITY_MAPPING), dtype=np.float32)
    for cls, w in zip(present_classes, weights):
        class_weights_array[cls] = np.sqrt(w)
    class_weights = torch.tensor(class_weights_array, dtype=torch.float)
    logger.info(f"Class weights (sqrt-dampened): {dict(zip(SEVERITY_MAPPING.keys(), class_weights_array))}")

    tokenizer = AutoTokenizer.from_pretrained(base_model)
    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    def tokenize_function(examples):
        tokenized = tokenizer(
            examples["description"],
            padding=True,
            truncation=True,
            max_length=512,
        )
        tokenized["labels"] = [
            SEVERITY_MAPPING[label] for label in examples["severity_label"]
        ]
        return tokenized

    columns_to_remove = [
        col
        for col in dataset["train"].column_names
        if col not in ["description", "severity_label"]
    ]

    tokenized_datasets = dataset.map(
        tokenize_function,
        batched=True,
        remove_columns=columns_to_remove,
    )

    num_labels = len(SEVERITY_MAPPING)
    model = AutoModelForSequenceClassification.from_pretrained(
        base_model,
        num_labels=num_labels,
        id2label=ID2LABEL,
        label2id=SEVERITY_MAPPING,
    )

    training_args = TrainingArguments(
        output_dir=model_save_dir,
        eval_strategy="epoch",
        save_strategy="epoch",
        learning_rate=3e-5,
        per_device_train_batch_size=8 if "roberta" in base_model else 16,
        per_device_eval_batch_size=8 if "roberta" in base_model else 16,
        num_train_epochs=5,
        weight_decay=0.01,
        logging_dir="./logs",
        logging_steps=10,
        save_total_limit=3,
        load_best_model_at_end=True,
        metric_for_best_model="accuracy",
        greater_is_better=True,
        push_to_hub=True,
        hub_model_id=repo_id,
    )

    trainer = WeightedTrainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_datasets["train"],
        eval_dataset=tokenized_datasets["test"],
        data_collator=data_collator,
        compute_metrics=compute_metrics,
        class_weights=class_weights,
    )

    try:
        trainer.train()
    finally:
        model.save_pretrained(model_save_dir)
        tokenizer.save_pretrained(model_save_dir)

    trainer.push_to_hub()
    tokenizer.push_to_hub(repo_id)


def main():
    parser = argparse.ArgumentParser(
        description="Train a vulnerability classification model with severity mapping for Chinese NVD."
    )
    parser.add_argument(
        "--base-model",
        dest="base_model",
        default="distilbert-base-uncased",
        choices=[
            "distilbert-base-uncased",
            "roberta-base",
            "google-bert/bert-base-chinese",
            "hfl/chinese-macbert-base",
            "hfl/chinese-bert-wwm-ext",
        ],
        help="Base model to use.",
    )
    parser.add_argument(
        "--dataset-id",
        dest="dataset_id",
        default="CIRCL/vulnerability-scores",
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

    args = parser.parse_args()

    dir_path = Path(args.model_save_dir)
    if dir_path.exists() and dir_path.is_dir():
        shutil.rmtree(dir_path)

    logger.info(f"Using base model: {args.base_model}")
    logger.info(f"Dataset ID: {args.dataset_id}")
    logger.info(f"Repo ID: {args.repo_id}")
    logger.info(f"Saving model to: {args.model_save_dir}")
    logger.info("Starting the training process…")

    train(args.base_model, args.dataset_id, args.repo_id, args.model_save_dir)


if __name__ == "__main__":
    main()
