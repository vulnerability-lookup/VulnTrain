"""Train a multi-label MITRE ATT&CK technique classifier from vulnerability
descriptions.

Uses the CIRCL/vulnerability-attack-techniques dataset (see
docs/attack-techniques-dataset.md for the methodology). Unlike the CWE
classifier this is a multi-label task: a CVE legitimately maps to several
techniques (exploitation technique plus impacts), so the model uses a
sigmoid head with binary cross-entropy loss.

Label vocabulary: sub-techniques are collapsed to their parent technique
(T1059.007 -> T1059) and only techniques with at least --min-examples
occurrences in the training split are kept, so the model never learns
labels it has effectively never seen. The `techniques_derived` column
(weak CVE2CAPEC labels) is intentionally ignored.

The model output must be presented as candidate techniques for analyst
review, not as an authoritative mapping.
"""

import argparse
import json
import logging
import os
import shutil
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Optional

import numpy as np
import torch
from codecarbon import EmissionsTracker
from datasets import concatenate_datasets, load_dataset
from sklearn.metrics import f1_score, precision_score, recall_score
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    Trainer,
    TrainingArguments,
)

from vulntrain.utils import push_emissions_report

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def collapse_subtechnique(technique_id: str) -> str:
    """T1059.007 -> T1059; parent techniques are returned unchanged."""
    return technique_id.split(".")[0]


def recall_at_k(logits: np.ndarray, labels: np.ndarray, k: int) -> float:
    """Average fraction of a sample's true techniques found in the top-k
    scored ones. The model is used to suggest candidate techniques, so what
    matters is whether the right ones appear among the top suggestions."""
    top_k = np.argsort(logits, axis=1)[:, ::-1][:, :k]
    recalls = []
    for sample_top, sample_labels in zip(top_k, labels):
        true_indices = np.flatnonzero(sample_labels)
        if len(true_indices) == 0:
            continue
        hits = np.isin(true_indices, sample_top).sum()
        recalls.append(hits / len(true_indices))
    return float(np.mean(recalls)) if recalls else 0.0


def compute_metrics(eval_pred: Any) -> dict[str, float]:
    logits, labels = eval_pred
    # sigmoid(logit) >= 0.5 is equivalent to logit >= 0
    predictions = (logits >= 0.0).astype(int)
    return {
        "f1_micro": f1_score(labels, predictions, average="micro", zero_division=0),
        "f1_macro": f1_score(labels, predictions, average="macro", zero_division=0),
        "precision_micro": precision_score(
            labels, predictions, average="micro", zero_division=0
        ),
        "recall_micro": recall_score(
            labels, predictions, average="micro", zero_division=0
        ),
        "recall_at_3": recall_at_k(logits, labels, 3),
        "recall_at_5": recall_at_k(logits, labels, 5),
    }


class MultiLabelTrainer(Trainer):
    """Trainer using BCE-with-logits, optionally weighted per label to
    counter class imbalance."""

    def __init__(
        self, *args: Any, pos_weight: Optional[torch.Tensor] = None, **kwargs: Any
    ):
        super().__init__(*args, **kwargs)
        self.pos_weight = pos_weight

    def compute_loss(
        self,
        model: Any,
        inputs: dict[str, Any],
        return_outputs: bool = False,
        num_items_in_batch: Optional[int] = None,
    ) -> Any:
        labels = inputs["labels"]
        outputs = model(**inputs)
        logits = outputs.get("logits")
        pos_weight = (
            self.pos_weight.to(logits.device) if self.pos_weight is not None else None
        )
        loss_fct = torch.nn.BCEWithLogitsLoss(pos_weight=pos_weight)
        loss = loss_fct(logits, labels.float())
        return (loss, outputs) if return_outputs else loss


def build_label_vocabulary(
    train_techniques: list[list[str]], min_examples: int, keep_subtechniques: bool
) -> list[str]:
    counts: Counter[str] = Counter()
    for techniques in train_techniques:
        labels = {
            technique if keep_subtechniques else collapse_subtechnique(technique)
            for technique in techniques
        }
        counts.update(labels)
    vocabulary = sorted(
        technique for technique, count in counts.items() if count >= min_examples
    )
    dropped = len(counts) - len(vocabulary)
    logger.info(
        f"Label vocabulary: {len(vocabulary)} techniques "
        f"({dropped} dropped for having fewer than {min_examples} examples)"
    )
    return vocabulary


def train(
    base_model: str,
    dataset_id: str,
    repo_id: str,
    model_save_dir: str,
    min_examples: int = 5,
    keep_subtechniques: bool = False,
    class_weights_mode: str = "balanced",
    epochs: int = 40,
    learning_rate: float = 1e-5,
    batch_size: int = 16,
    max_length: Optional[int] = None,
    extra_dataset_id: Optional[str] = None,
    extra_max_rows: Optional[int] = None,
    train_fraction: float = 1.0,
    seed: int = 42,
    val_split: float = 0.1,
    deterministic: bool = False,
    push: bool = True,
) -> None:
    # full_determinism sets CUDA_LAUNCH_BLOCKING=1, which deadlocks
    # multi-GPU DataParallel on the first training step (observed on
    # 2x H100: 0 steps in 8 hours). Fail fast instead of hanging.
    if deterministic and torch.cuda.device_count() > 1:
        sys.exit(
            "--deterministic deadlocks with multiple visible GPUs "
            f"({torch.cuda.device_count()} detected): full_determinism sets "
            "CUDA_LAUNCH_BLOCKING=1, which stalls DataParallel. Restrict to "
            "one GPU, e.g. CUDA_VISIBLE_DEVICES=0, and adjust --batch-size "
            "to keep the effective batch size."
        )
    if not 0.0 < train_fraction <= 1.0:
        sys.exit(f"--train-fraction must be in (0, 1], got {train_fraction}")

    dataset = load_dataset(dataset_id)

    # Carve a validation split out of the gold TRAIN portion for best-checkpoint
    # selection. Selecting the best epoch on the test split both leaks the test
    # set into model selection and turns the reported metric into an argmax over
    # many noisy evaluations of a small set; a dedicated validation split keeps
    # the test split strictly held out. Carved before any extra rows are merged
    # so the selection yardstick stays gold-only across expansion sizes.
    if val_split > 0.0:
        gold_split = dataset["train"].train_test_split(test_size=val_split, seed=seed)
        dataset["train"] = gold_split["train"]
        dataset["validation"] = gold_split["test"]

    # Subsample the gold TRAIN portion for a gold-size scaling curve. A fixed
    # shuffle seed keeps the subsets nested across fractions and identical
    # across run seeds (mirroring the nested-subset design of the LLM
    # expansion sweep); applied after the validation carve-out so the
    # selection yardstick stays constant across fractions, and before any
    # extra rows are merged so the fraction applies to gold data only.
    if train_fraction < 1.0:
        keep = int(len(dataset["train"]) * train_fraction)
        dataset["train"] = dataset["train"].shuffle(seed=13).select(range(keep))
        logger.info(
            f"Subsampled gold train to {keep} rows (fraction {train_fraction})"
        )

    # Fold extra (e.g. LLM-labeled) rows into the TRAIN split only, so the gold
    # test split stays an untouched yardstick for the gold+LLM-union experiment.
    if extra_dataset_id is not None:
        extra = load_dataset(extra_dataset_id)
        extra_train = extra["train"] if "train" in extra else extra[next(iter(extra))]
        # Cap the number of extra rows for expansion-size scaling sweeps. Taking
        # the first N rows keeps the sizes nested (100 rows ⊂ 300 ⊂ all) so the
        # scaling curve is measured on a consistent, growing subset.
        if extra_max_rows is not None and extra_max_rows < len(extra_train):
            extra_train = extra_train.select(range(extra_max_rows))
        shared = [c for c in dataset["train"].column_names if c in extra_train.column_names]
        dataset["train"] = concatenate_datasets(
            [dataset["train"].select_columns(shared), extra_train.select_columns(shared)]
        )
        logger.info(
            f"Merged {len(extra_train)} extra rows from {extra_dataset_id} into "
            f"train (now {len(dataset['train'])}); test split left untouched"
        )

    label_vocabulary = build_label_vocabulary(
        dataset["train"]["techniques"], min_examples, keep_subtechniques
    )
    label_to_id = {label: idx for idx, label in enumerate(label_vocabulary)}
    id_to_label = {idx: label for label, idx in label_to_id.items()}

    def encode_example(example: dict[str, Any]) -> dict[str, Any]:
        multi_hot = [0.0] * len(label_vocabulary)
        for technique in example["techniques"]:
            label = (
                technique if keep_subtechniques else collapse_subtechnique(technique)
            )
            if label in label_to_id:
                multi_hot[label_to_id[label]] = 1.0
        example["labels"] = multi_hot
        return example

    dataset = dataset.map(encode_example)
    dataset = dataset.filter(lambda x: sum(x["labels"]) > 0)
    logger.info(
        f"Train examples: {len(dataset['train'])}, "
        f"test examples: {len(dataset['test'])}"
        + (
            f", validation examples: {len(dataset['validation'])}"
            if val_split > 0.0
            else ""
        )
    )

    pos_weight: Optional[torch.Tensor] = None
    if class_weights_mode in ("sqrt", "balanced"):
        label_matrix = np.array(dataset["train"]["labels"], dtype=np.float32)
        positives = label_matrix.sum(axis=0)
        negatives = len(label_matrix) - positives
        # Clip so rare labels do not dominate the loss entirely.
        weights = np.clip(negatives / np.maximum(positives, 1.0), 1.0, 20.0)
        if class_weights_mode == "sqrt":
            weights = np.sqrt(weights)
        pos_weight = torch.tensor(weights, dtype=torch.float)
        logger.info(
            f"BCE pos_weight ({class_weights_mode}): "
            f"min={weights.min():.3f} max={weights.max():.3f}"
        )
    else:
        logger.info("BCE pos_weight: disabled (uniform loss)")

    tokenizer = AutoTokenizer.from_pretrained(base_model)

    if max_length is None:
        max_length = min(tokenizer.model_max_length, 8192)
    logger.info(f"Tokenizing with max_length={max_length}")

    def tokenize_function(examples: dict[str, Any]) -> Any:
        texts = [
            f"{title}\n{description}".strip()
            for title, description in zip(examples["title"], examples["description"])
        ]
        # No padding here: DataCollatorWithPadding pads each batch dynamically.
        return tokenizer(texts, truncation=True, max_length=max_length)

    tokenized_dataset = dataset.map(tokenize_function, batched=True)
    tokenized_dataset = tokenized_dataset.remove_columns(
        [column for column in dataset["train"].column_names if column != "labels"]
    )

    model = AutoModelForSequenceClassification.from_pretrained(
        base_model,
        num_labels=len(label_vocabulary),
        problem_type="multi_label_classification",
    )

    training_args = TrainingArguments(
        output_dir=model_save_dir,
        eval_strategy="epoch",
        save_strategy="epoch",
        save_total_limit=2,
        learning_rate=learning_rate,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size,
        num_train_epochs=epochs,
        weight_decay=0.01,
        logging_steps=20,
        load_best_model_at_end=True,
        metric_for_best_model="f1_macro",
        greater_is_better=True,
        seed=seed,
        data_seed=seed,
        full_determinism=deterministic,
        hub_model_id=repo_id,
    )

    selection_split = "validation" if val_split > 0.0 else "test"
    trainer = MultiLabelTrainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_dataset["train"],
        eval_dataset=tokenized_dataset[selection_split],
        processing_class=tokenizer,
        data_collator=DataCollatorWithPadding(tokenizer),
        compute_metrics=compute_metrics,
        pos_weight=pos_weight,
    )

    # Save emissions data inside the model directory so it gets pushed to the
    # Hub together with the model (default output_dir is the CWD, which is
    # never uploaded).
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

        model.config.id2label = id_to_label
        model.config.label2id = label_to_id
        model.config.num_labels = len(label_vocabulary)
        model.config.problem_type = "multi_label_classification"
        model.config.save_pretrained(model_save_dir)

    # Always report final metrics on the held-out test split (during training
    # the trainer evaluates the selection split, which may be the validation
    # carve-out).
    metrics = trainer.evaluate(eval_dataset=tokenized_dataset["test"])
    metrics_path = Path(model_save_dir) / "metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=4)
    logger.info(f"Evaluation metrics: {metrics}")

    if push:
        trainer.push_to_hub()
        tokenizer.push_to_hub(repo_id)
        if push_emissions_report(model_save_dir, repo_id):
            logger.info(f"Emissions report pushed to {repo_id}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train a multi-label MITRE ATT&CK technique classifier "
        "from vulnerability descriptions."
    )
    parser.add_argument(
        "--base-model",
        nargs="+",
        required=True,
        help="One or more base models to fine-tune (e.g. roberta-base).",
    )
    parser.add_argument(
        "--dataset-id",
        default="CIRCL/vulnerability-attack-techniques",
        help="Hugging Face dataset with 'techniques', 'title' and 'description'.",
    )
    parser.add_argument(
        "--extra-dataset-id",
        dest="extra_dataset_id",
        default=None,
        help="Optional extra dataset (e.g. an LLM-labeled expansion) whose rows "
        "are folded into the TRAIN split only. The test split is left untouched "
        "so it stays a gold-only yardstick.",
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
        "--min-examples",
        type=int,
        default=5,
        help="Keep only techniques with at least this many training examples.",
    )
    parser.add_argument(
        "--keep-subtechniques",
        action="store_true",
        help="Keep sub-technique labels instead of collapsing them to their "
        "parent technique.",
    )
    parser.add_argument(
        "--class-weights",
        dest="class_weights",
        default="balanced",
        choices=["none", "sqrt", "balanced"],
        help="Per-label positive weights for the BCE loss: 'none' (uniform), "
        "'sqrt' (sqrt-dampened) or 'balanced' (full negative/positive ratio, "
        "clipped at 20).",
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
    parser.add_argument(
        "--extra-max-rows",
        dest="extra_max_rows",
        type=int,
        default=None,
        help="Cap the number of --extra-dataset-id rows folded into train (first "
        "N rows). Use to sweep expansion size from one labeled dataset; the "
        "subsets are nested (N=100 rows are a subset of N=300).",
    )
    parser.add_argument(
        "--train-fraction",
        dest="train_fraction",
        type=float,
        default=1.0,
        help="Fraction of the gold train split to keep (after the validation "
        "carve-out, before extra rows are merged), for a gold-size scaling "
        "curve. A fixed shuffle seed keeps subsets nested across fractions "
        "and identical across run seeds.",
    )
    parser.add_argument(
        "--val-split",
        dest="val_split",
        type=float,
        default=0.1,
        help="Fraction of the gold train split held out for best-checkpoint "
        "selection so the test split stays strictly held out. 0 restores the "
        "previous behaviour of selecting on the test split.",
    )
    parser.add_argument(
        "--deterministic",
        action="store_true",
        help="Fully deterministic training (transformers full_determinism: "
        "deterministic CUDA algorithms + CUBLAS workspace config). Makes "
        "fixed-seed runs bit-reproducible, but sets CUDA_LAUNCH_BLOCKING=1, "
        "which DEADLOCKS multi-GPU DataParallel (the trainer refuses to "
        "start with >1 visible GPU) and slows single-GPU training. Reserve "
        "for single-GPU archival runs (CUDA_VISIBLE_DEVICES=0); multi-seed "
        "sweeps do not need it.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for training (weight init, data shuffling). Vary it "
        "across runs to measure run-to-run variance.",
    )
    parser.add_argument(
        "--no-push",
        action="store_true",
        help="Do not push the model to the Hugging Face Hub (dry run).",
    )
    args = parser.parse_args()

    for base_model in args.base_model:
        model_name_sanitized = base_model.replace("/", "-")
        save_dir = os.path.join(args.model_save_dir, model_name_sanitized)

        logger.info("=" * 80)
        logger.info(f"Training with base model: {base_model}")
        logger.info(f"Model will be saved to: {save_dir}")
        logger.info(f"Will be pushed to Hub at: {args.repo_id}")
        logger.info("=" * 80)

        dir_path = Path(save_dir)
        if dir_path.exists() and dir_path.is_dir():
            shutil.rmtree(dir_path)

        train(
            base_model,
            args.dataset_id,
            args.repo_id,
            save_dir,
            min_examples=args.min_examples,
            keep_subtechniques=args.keep_subtechniques,
            class_weights_mode=args.class_weights,
            epochs=args.epochs,
            learning_rate=args.learning_rate,
            batch_size=args.batch_size,
            max_length=args.max_length,
            extra_dataset_id=args.extra_dataset_id,
            extra_max_rows=args.extra_max_rows,
            train_fraction=args.train_fraction,
            seed=args.seed,
            val_split=args.val_split,
            deterministic=args.deterministic,
            push=not args.no_push,
        )


if __name__ == "__main__":
    main()
