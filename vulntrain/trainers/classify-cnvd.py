import argparse
import logging
import shutil
from collections import Counter
from pathlib import Path

import evaluate
import numpy as np
from codecarbon import track_emissions
from datasets import DatasetDict, load_dataset
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
)

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define severity label mapping
SEVERITY_MAPPING = {"Low": 0, "Medium": 1, "High": 2}


def compute_metrics(eval_pred):
    """Compute accuracy for model evaluation."""
    metric = evaluate.load("accuracy")
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=-1)
    return metric.compute(predictions=predictions, references=labels)


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


@track_emissions(project_name="VulnTrain", allow_multiple_runs=True)
def train(base_model, dataset_id, repo_id, model_save_dir="./vulnerability-classify"):
    dataset = load_dataset(dataset_id)

    if not isinstance(dataset, DatasetDict) or "train" not in dataset:
        dataset = dataset.train_test_split(test_size=0.2, seed=42)

    # logger.info("Example from raw dataset:")
    # logger.info(dataset["train"][0])

    dataset = dataset.map(map_cvss_to_severity)

    dataset = dataset.filter(lambda x: x["severity"] in ["低", "中", "高"])

    label_counter = Counter([ex["severity_label"] for ex in dataset["train"]])
    logger.info(f"Label distribution after filtering: {label_counter}")

    if len(dataset["train"]) == 0:
        raise ValueError(
            "No training data left after filtering. Please check the dataset and label mapping."
        )

    # logger.info(f"Remaining examples: {len(dataset['train'])}")
    # logger.info("Example after label mapping:")
    # logger.info(dataset["train"][0])

    # dataset = dataset.map(flatten_description)
    # logger.info("Example after flattening description:")
    # logger.info(dataset["train"][0])

    tokenizer = AutoTokenizer.from_pretrained(base_model)

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
        id2label={v: k for k, v in SEVERITY_MAPPING.items()},
        label2id=SEVERITY_MAPPING,
    )

    # Define training arguments
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
        save_total_limit=2,
        load_best_model_at_end=True,
        push_to_hub=True,
        hub_model_id=repo_id,
        # remove_unused_columns=False,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_datasets["train"],
        eval_dataset=tokenized_datasets["test"],
        tokenizer=tokenizer,
        compute_metrics=compute_metrics,
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
