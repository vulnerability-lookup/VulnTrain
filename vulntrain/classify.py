import argparse

import evaluate  # type: ignore[import-untyped]
import numpy as np
from datasets import load_dataset  # type: ignore[import-untyped]
from transformers import (  # type: ignore[import-untyped]
    AutoModelForSequenceClassification,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
)

"""
Automatically classify new vulnerabilities based on their descriptions,
even if they don’t have CVSS scores.

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
def map_cvss_to_severity(elem):
    cvss_scores = [elem.get("cvss_v4_0"), elem.get("cvss_v3_1"), elem.get("cvss_v3_0"), elem.get("cvss_v2_0")]
    cvss_scores = [score for score in cvss_scores if score is not None]
    
    if not cvss_scores:
        return None  # Remove this entry
    
    highest_cvss = max(cvss_scores)
    
    if highest_cvss >= 9.0:
        elem["severity_label"] = SEVERITY_MAPPING["Critical"]
    elif highest_cvss >= 7.0:
        elem["severity_label"] = SEVERITY_MAPPING["High"]
    elif highest_cvss >= 4.0:
        elem["severity_label"] = SEVERITY_MAPPING["Medium"]
    else:
        elem["severity_label"] = SEVERITY_MAPPING["Low"]
    
    return elem

# Load dataset from Hugging Face
dataset_id = "CIRCL/vulnerability-scores"
dataset = load_dataset(dataset_id)

# Map severity labels and remove None values
dataset = dataset.map(map_cvss_to_severity)
dataset = dataset.filter(lambda x: x is not None)  # Remove unknown severities

# Tokenization
tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")

def tokenize_function(elem):
    return tokenizer(elem["description"], padding="max_length", truncation=True)

tokenized_datasets = dataset.map(tokenize_function, batched=True)

# Define model
model_name = "distilbert-base-uncased"
num_labels = len(SEVERITY_MAPPING)  # 4 classes

model = AutoModelForSequenceClassification.from_pretrained(
    model_name, 
    num_labels=num_labels, 
    id2label={v: k for k, v in SEVERITY_MAPPING.items()},  # Mapping indices to labels
    label2id=SEVERITY_MAPPING,  # Mapping labels to indices
)

# Define training arguments
training_args = TrainingArguments(
    output_dir="./results",          # Output directory
    evaluation_strategy="epoch",      # Evaluate every epoch
    save_strategy="epoch",            # Save model every epoch
    learning_rate=2e-5,
    per_device_train_batch_size=16,
    per_device_eval_batch_size=16,
    num_train_epochs=5,
    weight_decay=0.01,
    logging_dir="./logs",
    logging_steps=10,
    load_best_model_at_end=True,
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
trainer.train()


def main():
    parser = argparse.ArgumentParser(
        description="Train a vulnerability classification model."
    )
    parser.add_argument("--upload", action="store_true", help="Upload dataset to Hugging Face")