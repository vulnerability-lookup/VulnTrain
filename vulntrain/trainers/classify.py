import argparse
import logging
import shutil
from pathlib import Path

import evaluate
import numpy as np
from codecarbon import track_emissions
from datasets import load_dataset
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
)

"""
Automatically classify new vulnerabilities based on their descriptions,
even if they don't have CVSS scores.

Currently tested with distilbert-base-uncased and roberta-base.
"""

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define severity label mapping
SEVERITY_MAPPING = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def compute_metrics(eval_pred):
    """Compute accuracy and F1-score for model evaluation."""
    metric = evaluate.load("accuracy")
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=-1)
    return metric.compute(predictions=predictions, references=labels)


# Define severity mapping function
def map_cvss_to_severity(example):
    def to_float(value):
        try:
            return float(value) if value is not None else None
        except ValueError:
            return None

    cvss_v4_0 = to_float(example.get("cvss_v4_0"))
    cvss_v3_1 = to_float(example.get("cvss_v3_1"))
    cvss_v3_0 = to_float(example.get("cvss_v3_0"))
    cvss_v2_0 = to_float(example.get("cvss_v2_0"))

    severity_score = next(
        (
            score
            for score in [cvss_v4_0, cvss_v3_1, cvss_v3_0, cvss_v2_0]
            if score is not None
        ),
        None,
    )

    if severity_score is None:
        severity_label = "Unknown"
    elif severity_score >= 9.0:
        severity_label = "Critical"
    elif severity_score >= 7.0:
        severity_label = "High"
    elif severity_score >= 4.0:
        severity_label = "Medium"
    else:
        severity_label = "Low"

    example["severity_label"] = severity_label
    return example


@track_emissions(project_name="VulnTrain", allow_multiple_runs=True)
def train(base_model, dataset_id, repo_id, model_save_dir="./vulnerability-classify"):
    # Load dataset from Hugging Face
    dataset = load_dataset(dataset_id)

    # Map severity labels
    dataset = dataset.map(map_cvss_to_severity)

    # Filter out entries with no severity_label and with unknown keys
    dataset = dataset.filter(lambda x: "severity_label" in x)
    dataset = dataset.filter(lambda x: x["severity_label"] in SEVERITY_MAPPING)

    # Tokenization with labels
    tokenizer = AutoTokenizer.from_pretrained(base_model)

    def tokenize_function(elem):
        tokenized = tokenizer(
            elem["description"],
            padding="max_length",
            truncation=True,
        )

        # Convert list of severity labels to integers
        tokenized["labels"] = [
            int(SEVERITY_MAPPING.get(label, -1)) for label in elem["severity_label"]
        ]

        return tokenized

    tokenized_datasets = dataset.map(tokenize_function, batched=True)
    # print(tokenized_datasets["test"])

    # Define model
    num_labels = len(SEVERITY_MAPPING)  # 4 classes

    model = AutoModelForSequenceClassification.from_pretrained(
        base_model,
        num_labels=num_labels,
        id2label={
            v: k for k, v in SEVERITY_MAPPING.items()
        },  # Mapping indices to labels
        label2id=SEVERITY_MAPPING,  # Mapping labels to indices
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

    # Create Trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_datasets["train"],
        eval_dataset=tokenized_datasets["test"],
        tokenizer=tokenizer,
        compute_metrics=compute_metrics,
    )

    # Train model
    try:
        trainer.train()
    finally:
        model.save_pretrained(model_save_dir)
        tokenizer.save_pretrained(model_save_dir)

    trainer.push_to_hub()
    tokenizer.push_to_hub(repo_id)


def main():
    parser = argparse.ArgumentParser(
        description="Train a vulnerability classification model with a mapping on the severity."
    )
    parser.add_argument(
        "--base-model",
        dest="base_model",
        default="distilbert-base-uncased",
        choices=["distilbert-base-uncased", "roberta-base"],
        help="Base model to use.",
    )
    parser.add_argument(
        "--dataset-id",
        dest="dataset_id",
        default="CIRCL/vulnerability-scores",
        help="Path of the dataset. Local dataset or repository on the HF hub.",
    )
    parser.add_argument(
        "--repo-id",
        dest="repo_id",
        required=True,
        help="The name of the repository you want to push your object to. It should contain your organization name when pushing to a given organization.",
    )
    parser.add_argument(
        "--model-save-dir",
        dest="model_save_dir",
        default="results",
        help="The path to a directory where the tokenizer and the model will be saved.",
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
