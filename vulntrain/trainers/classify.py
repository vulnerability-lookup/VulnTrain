import argparse

import evaluate
import numpy as np
from codecarbon import track_emissions  # type: ignore[import-untyped]
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

Currently using distilbert-base-uncased or bert-base-uncased.
"""

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
def train(model_name):
    base_model = "distilbert-base-uncased"
    model_path = "./vulnerability"

    # Load dataset from Hugging Face
    dataset_id = "CIRCL/vulnerability-scores"
    dataset = load_dataset(dataset_id)

    # Map severity labels 
    dataset = dataset.map(map_cvss_to_severity)

    # Filter out entries with no severity_label
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
        
        # Convert list of labels to integers explicitly
        tokenized["labels"] = [int(SEVERITY_MAPPING.get(label, -1)) for label in elem["severity_label"]]

        # print(f"Raw severity labels: {elem['severity_label']}")
        # print(f"Mapped labels: {tokenized['labels']}")s

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
        output_dir="./results",
        evaluation_strategy="epoch",
        save_strategy="epoch",
        learning_rate=2e-5,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=16,
        num_train_epochs=5,
        weight_decay=0.01,
        logging_dir="./logs",
        logging_steps=10,
        load_best_model_at_end=True,
        push_to_hub=True,
        hub_model_id=model_name,
        # remove_unused_columns=False,  # Ensure dataset columns are kept
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
        model.save_pretrained(model_path)
        tokenizer.save_pretrained(model_path)

    # trainer.push_to_hub()
    # tokenizer.push_to_hub(model_name)


def main():
    parser = argparse.ArgumentParser(
        description="Train a vulnerability classification model."
    )
    parser.add_argument(
        "--model-name",
        dest="model_name",
        required=True,
        help="Name of the model to upload.",
    )

    args = parser.parse_args()

    train(args.model_name)


if __name__ == "__main__":
    main()
