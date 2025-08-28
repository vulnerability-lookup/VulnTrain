import argparse
import logging
import shutil
import base64
import torch
import json
import numpy as np
import evaluate
import os

from vulntrain.trainers.multilabel_model import MultiLabelClassificationModel
from codecarbon import track_emissions
from sklearn.metrics import f1_score, accuracy_score
from vulntrain.trainers import hierarchy
from pathlib import Path
from pathlib import Path
from sklearn.preprocessing import MultiLabelBinarizer
from transformers import Trainer, TrainingArguments, DataCollatorWithPadding, AutoTokenizer
from datasets import load_dataset
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
    DataCollatorWithPadding,
)

accuracy = evaluate.load("accuracy")

f1 = evaluate.load("f1", config_name="macro")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    labels = np.array(labels)

    try:
        probs = torch.sigmoid(torch.tensor(logits))
        predictions = (probs > 0.5).int().numpy()

        print("-----Predictions shape:", predictions.shape)
        print("-------Labels shape:", labels.shape)
        print("---------Predictions sums (first 5):", predictions.sum(axis=1)[:5])
        print("-----------Labels sums (first 5):", labels.sum(axis=1)[:5])

        f1_macro = f1_score(labels, predictions, average="macro", zero_division=0)
        exact_match = (predictions == labels).all(axis=1).mean()

    except Exception as e:
        print("Error in compute_metrics:", str(e))
        f1_macro = 0.0
        exact_match = 0.0

    return {
        "f1_macro": f1_macro,
        "exact_match": exact_match,
    }


@track_emissions(project_name="VulnTrain", allow_multiple_runs=True)
def train(base_model, dataset_id, repo_id, model_save_dir="./vulnerability-classify"):
    from vulntrain.trainers.multilabel_model import MultiLabelClassificationModel

    dataset = load_dataset(dataset_id)

    dataset = dataset["train"].filter(lambda x: x.get("cwe") and len(x["cwe"]) > 0)

    dataset = dataset.train_test_split(test_size=0.1)


    with open("vulntrain/trainers/deep_child_to_ancestor.json") as f:
        child_to_ancestor = json.load(f)

    all_cwes = set(child_to_ancestor.values())
    unique_cwes = sorted(all_cwes)

    logger.info(f"Targeting {len(unique_cwes)} unique CWE ancestor labels.")

    cwe_to_id = {cwe: idx for idx, cwe in enumerate(unique_cwes)}
    id_to_cwe = {idx: cwe for cwe, idx in cwe_to_id.items()}

    dataset = dataset.filter(lambda x: x.get("cwe") and len(x["cwe"]) > 0)

    def encode_example(example):
        cwes = example["cwe"] if isinstance(example["cwe"], list) else [example["cwe"]]
        label_set = set()

        for cwe in cwes:
            ancestor = child_to_ancestor.get(cwe, cwe)  
            if ancestor in cwe_to_id:
                label_set.add(ancestor)

        label_vector = [0] * len(cwe_to_id)
        for c in label_set:
            label_vector[cwe_to_id[c]] = 1

        example["labels"] = label_vector
        return example

    dataset = dataset.map(encode_example)
    #delete if no labels
    dataset = dataset.filter(lambda x: sum(x["labels"]) > 0)

    def count_pos_labels(ds):
        return sum(1 for ex in ds if sum(ex["labels"]) > 0)

    print("-------------- Train positives:", count_pos_labels(dataset["train"]))
    print("-------------- Test positives :", count_pos_labels(dataset["test"]))

    # finding the weights for each class
    label_matrix = np.array([example["labels"] for example in dataset["train"]])
    pos_counts = label_matrix.sum(axis=0)
    neg_counts = label_matrix.shape[0] - pos_counts
    pos_weight = torch.tensor(neg_counts / (pos_counts + 1e-6), dtype=torch.float)

    tokenizer = AutoTokenizer.from_pretrained(base_model)

    def extract_commit_text(example):
        patch_list = example.get("patches", [])
        description = example.get("description", "")

        patch_text = ""
        if isinstance(patch_list, list) and len(patch_list) > 0:
            patch = patch_list[0]
            commit_msg = patch.get("commit_message", "")
            patch_text_b64 = patch.get("patch_text_b64", "")
            try:
                decoded_patch = base64.b64decode(patch_text_b64).decode("utf-8")
            except Exception as e:
                print(">< Error decoding patch:", e)
                decoded_patch = ""
            patch_text = f"{commit_msg}\n{decoded_patch}".strip()

        full_text = f"{description}\n{patch_text}".strip()
        return full_text

    def tokenize_function(examples):
        texts = [extract_commit_text(example) for example in zip_examples(examples)]
        return tokenizer(texts, padding="max_length", truncation=True, max_length=512)

    def zip_examples(examples):
        keys = examples.keys()
        return [dict(zip(keys, values)) for values in zip(*examples.values())]

    tokenized_dataset = dataset.map(tokenize_function, batched=True)

    model = MultiLabelClassificationModel(
        model_name=base_model,
        num_labels=len(cwe_to_id),
        pos_weight=pos_weight,
    )

    model.pos_weight = pos_weight

    training_args = TrainingArguments(
        output_dir=model_save_dir,
        eval_strategy="epoch",
        save_strategy="epoch",
        learning_rate=3e-5,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=16,
        num_train_epochs=5,
        weight_decay=0.01,
        logging_dir="./logs",
        logging_steps=20,
        load_best_model_at_end=True,
        push_to_hub=True,
        hub_model_id=repo_id,
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
        torch.save(model.state_dict(), os.path.join(model_save_dir, "pytorch_model.bin"))
        
        tokenizer.save_pretrained(model_save_dir)
        config = {
            "num_labels": len(cwe_to_id),
            "id2label": id_to_cwe,
            "label2id": cwe_to_id,
        }
        with open(os.path.join(model_save_dir, "config.json"), "w") as f:
            json.dump(config, f, indent=4)

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
        default="roberta-base",
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