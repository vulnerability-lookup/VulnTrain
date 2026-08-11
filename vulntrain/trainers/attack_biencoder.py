"""Train a bi-encoder that scores vulnerability descriptions against the
official enterprise ATT&CK technique texts (label-semantics model).

Instead of a per-label classification head, one shared encoder embeds both
the CVE text and every candidate technique's official name+description
(mean-pooled, L2-normalized); the score for (CVE, technique) is a
learnable affine transform of their cosine similarity (SigLIP-style scale
and bias), trained with the same weighted binary cross-entropy, gold-only
validation carve-out and frozen label vocabulary as the classification
head, so the two architectures are directly comparable. Because scores
come from the label's *text* rather than label-specific head weights, the
model can also rank techniques it has no training examples for --- the
below-floor tail a classification head cannot address at all.

The technique texts used at training time are saved next to the model
(``technique_texts.json``) and the affine parameters and vocabulary are
recorded in the model config (``biencoder``), so the validator rebuilds
the exact training-time scoring function.
"""

import argparse
import json
import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Optional

import numpy as np
import torch
from codecarbon import EmissionsTracker
from datasets import load_dataset
from transformers import (
    AutoModel,
    AutoTokenizer,
    DataCollatorWithPadding,
    TrainingArguments,
)
from transformers.modeling_outputs import SequenceClassifierOutput

from vulntrain.attack_metadata import (
    CASCADE_SIGNAL,
    METADATA_SIGNALS,
    build_input_text,
)
from vulntrain.attack_texts import load_technique_texts
from vulntrain.datasets.attack_guesser_dataset import (
    ENTERPRISE_ATTACK_STIX_URL,
    download_file,
)
from vulntrain.trainers.attack_guesser import (
    MultiLabelTrainer,
    build_label_vocabulary,
    collapse_subtechnique,
    compute_metrics,
)
from vulntrain.utils import push_emissions_report

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BiEncoderModel(torch.nn.Module):
    """Shared encoder over CVE and technique texts; logits are an affine
    transform of the cosine similarities against all vocabulary techniques.

    The tokenized technique texts are registered as buffers, so they move
    with the model across devices and every forward pass re-encodes them
    with gradients --- both sides of the similarity are trained.
    """

    def __init__(
        self,
        encoder: Any,
        technique_encodings: dict[str, torch.Tensor],
        logit_scale: float = 10.0,
        logit_bias: float = -5.0,
    ):
        super().__init__()
        self.encoder = encoder
        self.config = encoder.config
        self.register_buffer("technique_input_ids", technique_encodings["input_ids"])
        self.register_buffer(
            "technique_attention_mask", technique_encodings["attention_mask"]
        )
        # The bias starts negative to counter the near-1 cosines of untuned
        # mean-pooled embeddings (anisotropy), but must leave logits above
        # the decision threshold reachable: scale s and bias b cap logits
        # at s + b, and a cap <= 0 makes every threshold metric
        # structurally zero (observed with b = -10: f1_macro pinned at 0).
        self.logit_scale = torch.nn.Parameter(torch.tensor(float(logit_scale)))
        self.logit_bias = torch.nn.Parameter(torch.tensor(float(logit_bias)))

    def _embed(
        self, input_ids: torch.Tensor, attention_mask: torch.Tensor
    ) -> torch.Tensor:
        hidden = self.encoder(
            input_ids=input_ids, attention_mask=attention_mask
        ).last_hidden_state
        mask = attention_mask.unsqueeze(-1).float()
        pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)
        return torch.nn.functional.normalize(pooled, dim=1)

    def forward(
        self,
        input_ids: Optional[torch.Tensor] = None,
        attention_mask: Optional[torch.Tensor] = None,
        labels: Optional[torch.Tensor] = None,
    ) -> SequenceClassifierOutput:
        assert input_ids is not None and attention_mask is not None
        cve = self._embed(input_ids, attention_mask)
        techniques = self._embed(
            self.technique_input_ids, self.technique_attention_mask
        )
        logits = self.logit_scale * (cve @ techniques.T) + self.logit_bias
        loss = None
        if labels is not None:
            loss = torch.nn.functional.binary_cross_entropy_with_logits(
                logits, labels.float()
            )
        return SequenceClassifierOutput(loss=loss, logits=logits)


def train(
    base_model: str,
    dataset_id: str,
    repo_id: str,
    model_save_dir: str,
    min_examples: int = 5,
    class_weights_mode: str = "balanced",
    epochs: int = 40,
    learning_rate: float = 1e-5,
    batch_size: int = 16,
    max_length: int = 512,
    technique_max_length: int = 256,
    train_fraction: float = 1.0,
    seed: int = 42,
    val_split: float = 0.1,
    cache_dir: str = "~/.cache/vulntrain",
    push: bool = True,
    metadata_signals: Optional[list[str]] = None,
) -> None:
    if not 0.0 < train_fraction <= 1.0:
        sys.exit(f"--train-fraction must be in (0, 1], got {train_fraction}")

    dataset = load_dataset(dataset_id)

    # Same protocol as the classification trainer: validation carve-out
    # from the gold train split for best-checkpoint selection, optional
    # nested gold subsampling with the vocabulary frozen to the full split.
    if val_split > 0.0:
        gold_split = dataset["train"].train_test_split(test_size=val_split, seed=seed)
        dataset["train"] = gold_split["train"]
        dataset["validation"] = gold_split["test"]

    frozen_vocab_techniques = None
    if train_fraction < 1.0:
        frozen_vocab_techniques = dataset["train"]["techniques"]
        keep = int(len(dataset["train"]) * train_fraction)
        dataset["train"] = dataset["train"].shuffle(seed=13).select(range(keep))
        logger.info(
            f"Subsampled gold train to {keep} rows (fraction {train_fraction}); "
            "label vocabulary frozen to the full gold train split"
        )

    label_vocabulary = build_label_vocabulary(
        (
            frozen_vocab_techniques
            if frozen_vocab_techniques is not None
            else dataset["train"]["techniques"]
        ),
        min_examples,
        keep_subtechniques=False,
    )
    label_to_id = {label: idx for idx, label in enumerate(label_vocabulary)}

    stix_path = download_file(
        ENTERPRISE_ATTACK_STIX_URL, Path(cache_dir).expanduser(), "enterprise-attack.json"
    )
    technique_texts = load_technique_texts(stix_path, label_vocabulary)
    missing = [label for label in label_vocabulary if label not in technique_texts]
    if missing:
        sys.exit(f"No STIX text for vocabulary techniques {missing}; cannot train")

    def encode_example(example: dict[str, Any]) -> dict[str, Any]:
        multi_hot = [0.0] * len(label_vocabulary)
        for technique in example["techniques"]:
            label = collapse_subtechnique(technique)
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

    signals = sorted(metadata_signals or [])
    logger.info(
        f"Metadata input signals: {signals or 'none (description-only, v1 input)'}"
    )

    def tokenize_function(examples: dict[str, Any]) -> Any:
        n = len(examples["title"])
        columns = examples.keys()
        texts = [
            build_input_text(
                {column: examples[column][i] for column in columns}, signals
            )
            for i in range(n)
        ]
        return tokenizer(texts, truncation=True, max_length=max_length)

    tokenized_dataset = dataset.map(tokenize_function, batched=True)
    tokenized_dataset = tokenized_dataset.remove_columns(
        [column for column in dataset["train"].column_names if column != "labels"]
    )

    technique_encodings = tokenizer(
        [technique_texts[label] for label in label_vocabulary],
        padding=True,
        truncation=True,
        max_length=technique_max_length,
        return_tensors="pt",
    )
    logger.info(
        f"Encoding {len(label_vocabulary)} technique texts per step "
        f"(max_length={technique_max_length})"
    )

    model = BiEncoderModel(
        AutoModel.from_pretrained(base_model),
        {
            "input_ids": technique_encodings["input_ids"],
            "attention_mask": technique_encodings["attention_mask"],
        },
    )

    training_args = TrainingArguments(
        output_dir=model_save_dir,
        eval_strategy="epoch",
        save_strategy="epoch",
        save_total_limit=2,
        label_names=["labels"],
        learning_rate=learning_rate,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size,
        num_train_epochs=epochs,
        weight_decay=0.01,
        logging_steps=20,
        load_best_model_at_end=True,
        # The classification trainer selects on f1_macro, but threshold
        # metrics depend on the affine calibration here (an early or
        # miscalibrated model yields no positive predictions at all, and a
        # constant selection metric silently degenerates to the first
        # epoch); the bi-encoder is used as a ranker, so select on ranking.
        metric_for_best_model="recall_at_5",
        greater_is_better=True,
        seed=seed,
        data_seed=seed,
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
        # Save the (best) encoder as a plain AutoModel plus everything the
        # validator needs to rebuild the training-time scoring function.
        encoder = model.encoder
        logger.info(
            f"Trained affine calibration: logit_scale={model.logit_scale.item():.4f} "
            f"logit_bias={model.logit_bias.item():.4f}"
        )
        encoder.config.biencoder = {
            "labels": label_vocabulary,
            "logit_scale": float(model.logit_scale.item()),
            "logit_bias": float(model.logit_bias.item()),
            "technique_max_length": technique_max_length,
        }
        encoder.config.metadata_inputs = signals
        encoder.save_pretrained(model_save_dir)
        tokenizer.save_pretrained(model_save_dir)
        with open(Path(model_save_dir) / "technique_texts.json", "w") as f:
            json.dump(
                {label: technique_texts[label] for label in label_vocabulary},
                f,
                indent=2,
            )

    metrics = trainer.evaluate(eval_dataset=tokenized_dataset["test"])
    metrics_path = Path(model_save_dir) / "metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=4)
    logger.info(f"Evaluation metrics: {metrics}")

    if push:
        encoder.push_to_hub(repo_id)
        tokenizer.push_to_hub(repo_id)
        from huggingface_hub import HfApi

        HfApi().upload_file(
            path_or_fileobj=str(Path(model_save_dir) / "technique_texts.json"),
            path_in_repo="technique_texts.json",
            repo_id=repo_id,
        )
        if push_emissions_report(model_save_dir, repo_id):
            logger.info(f"Emissions report pushed to {repo_id}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train a bi-encoder scoring vulnerability descriptions "
        "against official ATT&CK technique texts (label-semantics model)."
    )
    parser.add_argument(
        "--base-model",
        nargs="+",
        required=True,
        help="One or more base encoders to fine-tune (e.g. roberta-base).",
    )
    parser.add_argument(
        "--dataset-id",
        default="CIRCL/vulnerability-attack-techniques",
        help="Hugging Face dataset with 'techniques', 'title' and 'description'.",
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
        "--metadata",
        nargs="+",
        choices=list(METADATA_SIGNALS) + [CASCADE_SIGNAL, "all"],
        default=[],
        help="Structured metadata signals appended (verbalized) to the CVE "
        "input text, exactly as in the classification trainer. Default: "
        "none (description-only, v1 input).",
    )
    parser.add_argument(
        "--min-examples",
        type=int,
        default=5,
        help="Keep only techniques with at least this many training examples "
        "(the same vocabulary floor as the classification trainer).",
    )
    parser.add_argument(
        "--class-weights",
        dest="class_weights",
        default="balanced",
        choices=["none", "sqrt", "balanced"],
        help="Per-label positive weights for the BCE loss, as in the "
        "classification trainer.",
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
        help="Per-device train and eval batch size. Every step additionally "
        "encodes all vocabulary technique texts.",
    )
    parser.add_argument(
        "--max-length",
        dest="max_length",
        type=int,
        default=512,
        help="Truncation length for the CVE input text.",
    )
    parser.add_argument(
        "--technique-max-length",
        dest="technique_max_length",
        type=int,
        default=256,
        help="Truncation length for the official technique texts.",
    )
    parser.add_argument(
        "--train-fraction",
        dest="train_fraction",
        type=float,
        default=1.0,
        help="Fraction of the gold train split to keep (after the validation "
        "carve-out), for scaling curves and smoke tests. The label "
        "vocabulary is frozen to the full gold train split.",
    )
    parser.add_argument(
        "--val-split",
        dest="val_split",
        type=float,
        default=0.1,
        help="Fraction of the gold train split held out for best-checkpoint "
        "selection so the test split stays strictly held out.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for training (weight init, data shuffling).",
    )
    parser.add_argument(
        "--cache-dir",
        default="~/.cache/vulntrain",
        help="Directory where the ATT&CK STIX data is cached.",
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
        logger.info(f"Training bi-encoder with base model: {base_model}")
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
            class_weights_mode=args.class_weights,
            epochs=args.epochs,
            learning_rate=args.learning_rate,
            batch_size=args.batch_size,
            max_length=args.max_length,
            technique_max_length=args.technique_max_length,
            train_fraction=args.train_fraction,
            seed=args.seed,
            val_split=args.val_split,
            cache_dir=args.cache_dir,
            push=not args.no_push,
            metadata_signals=(
                list(METADATA_SIGNALS) if "all" in args.metadata else args.metadata
            ),
        )


if __name__ == "__main__":
    main()
