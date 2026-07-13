import argparse
import base64
import json
import logging
import os
import re
import shutil
from pathlib import Path

import evaluate
import numpy as np
import torch
from codecarbon import EmissionsTracker
from datasets import load_dataset
from sklearn.metrics import accuracy_score, f1_score
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    Trainer,
    TrainingArguments,
)

from vulntrain.utils import push_emissions_report

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
    # Top-k accuracy: the model is used to suggest candidate CWEs, so what
    # matters is whether the right CWE appears among the top suggestions.
    top5 = np.argsort(logits, axis=1)[:, ::-1][:, :5]
    labels_column = np.asarray(labels).reshape(-1, 1)
    return {
        "accuracy": accuracy_score(labels, predictions),
        "f1_macro": f1_score(labels, predictions, average="macro", zero_division=0),
        "accuracy_top3": float(np.mean((top5[:, :3] == labels_column).any(axis=1))),
        "accuracy_top5": float(np.mean((top5 == labels_column).any(axis=1))),
    }


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


class FocalLossTrainer(Trainer):
    """Trainer subclass that applies focal loss for class imbalance.

    Focal loss down-weights easy (well-classified) examples and focuses
    training on hard ones. Unlike class weighting, it adapts per-example
    based on the model's current confidence, making it less likely to
    degrade majority-class performance.

    See: Lin et al., "Focal Loss for Dense Object Detection", 2017.
    """

    def __init__(self, *args, gamma=2.0, alpha=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.gamma = gamma
        self.alpha = alpha

    def compute_loss(
        self, model, inputs, return_outputs=False, num_items_in_batch=None
    ):
        labels = inputs.get("labels")
        outputs = model(**inputs)
        logits = outputs.get("logits")

        ce_loss = torch.nn.functional.cross_entropy(logits, labels, reduction="none")
        pt = torch.exp(-ce_loss)
        focal_loss = ((1 - pt) ** self.gamma) * ce_loss

        if self.alpha is not None:
            alpha_t = self.alpha.to(logits.device)[labels]
            focal_loss = alpha_t * focal_loss

        loss = focal_loss.mean()
        return (loss, outputs) if return_outputs else loss


def train(
    base_model,
    dataset_id,
    repo_id,
    model_save_dir="./vulnerability-classify",
    class_weights_mode="balanced",
    epochs=40,
    learning_rate=1e-5,
    batch_size=16,
    max_length=None,
):
    dataset = load_dataset(dataset_id)
    dataset = dataset["train"].filter(lambda x: x.get("cwe") and len(x["cwe"]) > 0)
    dataset = dataset.train_test_split(test_size=0.1)

    with open(Path(__file__).parent.parent / "data" / "deep_child_to_ancestor.json") as f:
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

    # Compute class weights for the (heavily imbalanced) training set
    from sklearn.utils.class_weight import compute_class_weight

    num_classes = len(cwe_to_id)

    class_weights = None
    if class_weights_mode in ("sqrt", "balanced", "focal"):
        all_labels = np.array([example["labels"] for example in dataset["train"]])
        present_classes = np.unique(all_labels)
        present_weights = compute_class_weight(
            class_weight="balanced", classes=present_classes, y=all_labels
        )
        class_weights_array = np.ones(num_classes, dtype=np.float32)
        for cls, weight in zip(present_classes, present_weights):
            if class_weights_mode == "sqrt":
                class_weights_array[cls] = np.sqrt(weight)
            else:
                class_weights_array[cls] = weight
        class_weights = torch.tensor(class_weights_array, dtype=torch.float)
        logger.info(
            f"Class weights ({class_weights_mode}): "
            f"min={class_weights_array.min():.3f} max={class_weights_array.max():.3f}"
        )
    else:
        logger.info("Class weights: disabled (uniform loss)")

    tokenizer = AutoTokenizer.from_pretrained(base_model)

    if max_length is None:
        max_length = min(tokenizer.model_max_length, 8192)
    logger.info(f"Tokenizing with max_length={max_length}")

    def extract_commit_text(example):
        description = example.get("description", "") or ""
        patch_list = example.get("patches", [])

        patch_texts = []
        if isinstance(patch_list, list):
            for patch in patch_list:
                commit_msg = patch.get("commit_message", "") or ""
                try:
                    decoded_patch = base64.b64decode(
                        patch.get("patch_text_b64", "") or ""
                    ).decode("utf-8")
                except Exception as e:
                    print(">< Error decoding patch:", e)
                    decoded_patch = ""
                patch_texts.append(f"{commit_msg}\n{decoded_patch}".strip())

        return "\n".join([description, *patch_texts]).strip()

    def zip_examples(examples):
        keys = examples.keys()
        return [dict(zip(keys, values)) for values in zip(*examples.values())]

    def tokenize_function(examples):
        texts = [extract_commit_text(example) for example in zip_examples(examples)]
        # No padding here: DataCollatorWithPadding pads each batch dynamically.
        return tokenizer(texts, truncation=True, max_length=max_length)

    tokenized_dataset = dataset.map(tokenize_function, batched=True)

    model = AutoModelForSequenceClassification.from_pretrained(
        base_model, num_labels=len(cwe_to_id)
    )

    training_args = TrainingArguments(
        output_dir=model_save_dir,
        eval_strategy="epoch",
        save_strategy="epoch",
        learning_rate=learning_rate,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size,
        num_train_epochs=epochs,
        weight_decay=0.01,
        logging_steps=20,
        load_best_model_at_end=True,
        metric_for_best_model="f1_macro",
        greater_is_better=True,
        hub_model_id=repo_id,
    )

    trainer_kwargs = dict(
        model=model,
        args=training_args,
        train_dataset=tokenized_dataset["train"],
        eval_dataset=tokenized_dataset["test"],
        processing_class=tokenizer,
        data_collator=DataCollatorWithPadding(tokenizer),
        compute_metrics=compute_metrics,
    )
    if class_weights_mode == "focal":
        trainer = FocalLossTrainer(**trainer_kwargs, gamma=2.0, alpha=class_weights)
    elif class_weights is not None:
        trainer = WeightedTrainer(**trainer_kwargs, class_weights=class_weights)
    else:
        trainer = Trainer(**trainer_kwargs)

    # Save emissions data inside the model directory so it gets pushed to the
    # Hub together with the model (default output_dir is the CWD, which is never
    # uploaded).
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

        model.config.id2label = id_to_cwe
        model.config.label2id = cwe_to_id
        model.config.num_labels = len(cwe_to_id)
        model.config.problem_type = "single_label_classification"

        model.config.save_pretrained(model_save_dir)

    metrics = trainer.evaluate()
    metrics_path = Path(model_save_dir) / "metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=4)

    trainer.push_to_hub()
    tokenizer.push_to_hub(repo_id)

    if push_emissions_report(model_save_dir, repo_id):
        logger.info(f"Emissions report pushed to {repo_id}")


def main():
    parser = argparse.ArgumentParser(
        description="Train a vulnerability classifier using CWE labels."
    )
    parser.add_argument(
        "--base-model",
        nargs="+",  # to make a list of models
        required=True,
        help="Un ou plusieurs modèles à tester (ex: roberta-base distilbert-base-uncased)",
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
    parser.add_argument(
        "--class-weights",
        dest="class_weights",
        default="balanced",
        choices=["none", "sqrt", "balanced", "focal"],
        help="Loss strategy for class imbalance: 'none' (uniform loss), "
        "'sqrt' (sqrt-dampened class weights), 'balanced' (full class "
        "weights) or 'focal' (focal loss with balanced alpha).",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=40,
        help="Number of training epochs.",
    )
    parser.add_argument(
        "--learning-rate",
        dest="learning_rate",
        type=float,
        default=1e-5,
        help="Learning rate.",
    )
    parser.add_argument(
        "--batch-size",
        dest="batch_size",
        type=int,
        default=16,
        help="Per-device train and eval batch size. Lower it for long-context "
        "models such as ModernBERT.",
    )
    parser.add_argument(
        "--max-length",
        dest="max_length",
        type=int,
        default=None,
        help="Tokenizer truncation length. Defaults to the model's maximum "
        "input length, capped at 8192 tokens.",
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

    for base_model in args.base_model:
        model_name_sanitized = base_model.replace("/", "-")
        # repo_id = f"{args.repo_id}-{model_name_sanitized}"
        repo_id = f"{args.repo_id}"
        save_dir = os.path.join(args.model_save_dir, model_name_sanitized)

        logger.info("=" * 80)
        logger.info(f"----------- Training with base model: {base_model}")
        logger.info(f"-------------- Model will be saved to: {save_dir}")
        logger.info(f"----------------- Will be pushed to Hub at: {repo_id}")
        logger.info("=" * 80)

        # Clean save dir if it exists
        dir_path = Path(save_dir)
        if dir_path.exists() and dir_path.is_dir():
            shutil.rmtree(dir_path)

        train(
            base_model,
            args.dataset_id,
            repo_id,
            save_dir,
            class_weights_mode=args.class_weights,
            epochs=args.epochs,
            learning_rate=args.learning_rate,
            batch_size=args.batch_size,
            max_length=args.max_length,
        )


if __name__ == "__main__":
    main()
