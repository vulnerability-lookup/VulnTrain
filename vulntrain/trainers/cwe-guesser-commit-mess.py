import argparse
import logging
import shutil
import base64
import torch
import json
import numpy as np
import evaluate
import os
import re
from collections import Counter

from transformers import AutoModelForSequenceClassification
from codecarbon import track_emissions
from sklearn.metrics import f1_score, accuracy_score
from pathlib import Path
from transformers import Trainer, TrainingArguments, DataCollatorWithPadding, AutoTokenizer
from datasets import load_dataset

accuracy = evaluate.load("accuracy")
f1 = evaluate.load("f1", config_name="macro")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def extract_cwe_id(cwe_string):
    match = re.search(r"CWE-(\d+)", cwe_string)
    if match:
        return match.group(1)
    return None

def compute_metrics(eval_pred):
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=1)
    return {
        "accuracy": accuracy_score(labels, predictions),
        "f1_macro": f1_score(labels, predictions, average="macro", zero_division=0),
    }

class WeightedTrainer(Trainer):
    def __init__(self, *args, class_weights=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.class_weights = class_weights

    def compute_loss(self, model, inputs, return_outputs=False, num_items_in_batch=None):
        labels = inputs.get("labels")
        outputs = model(**inputs)
        logits = outputs.get("logits")
        loss_fct = torch.nn.CrossEntropyLoss(weight=self.class_weights.to(logits.device))
        loss = loss_fct(logits, labels)
        return (loss, outputs) if return_outputs else loss

@track_emissions(project_name="VulnTrain", allow_multiple_runs=True)
def train(base_model, dataset_id, repo_id, model_save_dir="./vulnerability-classify"):
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

    def encode_example(example):
        cwes = example["cwe"] if isinstance(example["cwe"], list) else [example["cwe"]]
        for cwe in cwes:
            cwe_id = extract_cwe_id(cwe)
            if not cwe_id:
                continue
            ancestor = child_to_ancestor.get(cwe_id, cwe_id)
            if ancestor in cwe_to_id:
                example["labels"] = cwe_to_id[ancestor]
                return example
        example["labels"] = -1
        return example

    dataset = dataset.map(encode_example)
    dataset = dataset.filter(lambda x: x["labels"] != -1)

    print("-------------- Train examples:", len(dataset["train"]))
    print("-------------- Test examples :", len(dataset["test"]))

    # Compute class weights parce que classes desequilibrees
    label_counts = Counter(example["labels"] for example in dataset["train"])
    total = sum(label_counts.values())
    class_weights = []
    for i in range(len(cwe_to_id)):
        count = label_counts.get(i, 0)
        if count > 0:
            weight = total / (len(label_counts) * count)
        else:
            weight = 0.0
        class_weights.append(weight)
    class_weights = torch.tensor(class_weights, dtype=torch.float)

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

        return f"{description}\n{patch_text}".strip()

    def zip_examples(examples):
        keys = examples.keys()
        return [dict(zip(keys, values)) for values in zip(*examples.values())]

    def tokenize_function(examples):
        texts = [extract_commit_text(example) for example in zip_examples(examples)]
        return tokenizer(texts, padding="max_length", truncation=True, max_length=512)

    tokenized_dataset = dataset.map(tokenize_function, batched=True)

    model = AutoModelForSequenceClassification.from_pretrained(
        base_model,
        num_labels=len(cwe_to_id)
    )

    training_args = TrainingArguments(
        output_dir=model_save_dir,
        eval_strategy="epoch",
        save_strategy="epoch",
        learning_rate=1e-5,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=16,
        num_train_epochs=20,
        weight_decay=0.01,
        logging_dir="./logs",
        logging_steps=20,
        load_best_model_at_end=True,
        push_to_hub=True,
        hub_model_id=repo_id,
    )

    trainer = WeightedTrainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_dataset["train"],
        eval_dataset=tokenized_dataset["test"],
        tokenizer=tokenizer,
        data_collator=DataCollatorWithPadding(tokenizer),
        compute_metrics=compute_metrics,
        class_weights=class_weights,
    )

    from transformers import AutoConfig

    try:
        trainer.train()
    finally:
        model.save_pretrained(model_save_dir)
        tokenizer.save_pretrained(model_save_dir)

        config = AutoConfig.from_pretrained(base_model)

        config.id2label = id_to_cwe
        config.label2id = cwe_to_id
        config.num_labels = len(cwe_to_id)
        config.problem_type = "single_label_classification"

        config.save_pretrained(model_save_dir)


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
