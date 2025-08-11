import argparse
import logging
import shutil
from pathlib import Path
import base64

import json
from pathlib import Path

import numpy as np
from sklearn.preprocessing import MultiLabelBinarizer
from datasets import load_dataset

from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
    DataCollatorWithPadding,
)
from codecarbon import track_emissions
import evaluate

accuracy = evaluate.load("accuracy")
f1 = evaluate.load("f1")


# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=-1)

    print("- Predictions:", predictions[:20])
    print("- Labels     :", labels[:20])

    acc = accuracy.compute(predictions=predictions, references=labels)
    f1_score = f1.compute(predictions=predictions, references=labels, average="macro")
    return {**acc, **f1_score}



@track_emissions(project_name="VulnTrain", allow_multiple_runs=True)
def train(base_model, dataset_id, repo_id, model_save_dir="./vulnerability-classify"):
    dataset = load_dataset(dataset_id)
    if "test" not in dataset:
        dataset = dataset["train"].train_test_split(test_size=0.1)

    # Filter out samples without CWE
    dataset = dataset.filter(lambda x: x.get("cwe") and len(x["cwe"]) > 0)

    # Build list of unique CWE labels from the whole dataset
    all_cwes = [
        cwe for split in dataset.values()
        for row in split["cwe"]
        for cwe in (row if isinstance(row, list) else [row])
    ]

    unique_cwes = sorted(set(all_cwes))
    logger.info(f"Found {len(unique_cwes)} unique CWE labels.")

    cwe_to_id = {cwe: idx for idx, cwe in enumerate(unique_cwes)}
    id_to_cwe = {idx: cwe for cwe, idx in cwe_to_id.items()}

    # Encode first CWE as label
    def encode_example(example):
        first_cwe = example["cwe"][0] if isinstance(example["cwe"], list) else example["cwe"]
        example["label"] = cwe_to_id[first_cwe]
        return example

    dataset = dataset.map(encode_example)

    tokenizer = AutoTokenizer.from_pretrained(base_model)

    def extract_commit_text(patch_list):
        if isinstance(patch_list, list) and len(patch_list) > 0:
            patch = patch_list[0]
            commit_msg = patch.get("commit_message", "")
            patch_text_b64 = patch.get("patch_text_b64", "")
            try:
                decoded_patch = base64.b64decode(patch_text_b64).decode("utf-8")
            except Exception as e:
                print("❌ Error decoding patch:", e)
                decoded_patch = ""
            full_text = f"{commit_msg}\n{decoded_patch}".strip()
            if not full_text:
                print("⚠️ Empty text found.")
            return full_text
        return ""


    def tokenize_function(examples):
        texts = [extract_commit_text(patch) for patch in examples.get("patches", [])]
        # Ensure all texts are strings
        texts = [text if isinstance(text, str) else "" for text in texts]
        return tokenizer(
            texts,
            padding="max_length",
            truncation=True,
            max_length=512,
        )


    tokenized_dataset = dataset.map(tokenize_function, batched=True)
    tokenized_dataset = tokenized_dataset.rename_column("label", "labels")

    model = AutoModelForSequenceClassification.from_pretrained(
        base_model,
        num_labels=len(cwe_to_id),
        id2label=id_to_cwe,
        label2id=cwe_to_id,
    )

    training_args = TrainingArguments(
        output_dir=model_save_dir,
        eval_strategy="epoch",
        save_strategy="epoch",
        learning_rate=3e-5,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=16,
        num_train_epochs=1,
        weight_decay=0.01,
        logging_dir="./logs",
        logging_steps=20,
        load_best_model_at_end=True,
        push_to_hub=True,
        hub_model_id=repo_id,
        label_smoothing_factor=0.1,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_dataset["train"],
        eval_dataset=tokenized_dataset["test"],
        tokenizer=tokenizer,
        data_collator=DataCollatorWithPadding(tokenizer),
        compute_metrics=compute_metrics,
    )

    try:
        trainer.train()
    finally:
        model.save_pretrained(model_save_dir)
        tokenizer.save_pretrained(model_save_dir)


    print(tokenized_dataset)
    print(tokenized_dataset["train"][0])

    metrics = trainer.evaluate()
    metrics_path = Path(model_save_dir) / "metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=4)

    trainer.push_to_hub()
    tokenizer.push_to_hub(repo_id)


def main():
    parser = argparse.ArgumentParser(description="Train a vulnerability classifier using CWE labels.")
    parser.add_argument(
    "--base-model",
    default="gpt2-base" ,


    help="Base transformer model to use (e.g., roberta-base, codebert-base, etc.).",
)

    parser.add_argument(
        "--dataset-id",
        required=True,
        help="Hugging Face dataset repo ID or local dataset path (must have 'cwe' and 'description').",
    )
    parser.add_argument(
        "--repo-id",
        required=True,
        help="Hugging Face Hub repo ID to push the model to.",
    )
    parser.add_argument(
        "--model-save-dir",
        default="results",
        help="Directory to save the trained model locally.",
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