"""Evaluate ATT&CK technique suggestion approaches on the
CIRCL/vulnerability-attack-techniques test split.

Two methods share the same evaluation protocol (same label vocabulary,
same ranking metrics), so their numbers are directly comparable:

- ``similarity``: a zero-shot, SMET-style baseline. The vulnerability
  description and every candidate technique's official name+description
  (from the enterprise ATT&CK STIX data) are embedded with a sentence
  encoder; techniques are ranked by cosine similarity. No training data
  involved.
- ``classifier``: a fine-tuned multi-label model produced by
  vulntrain-train-attack-classification; techniques are ranked by logit.

The fine-tuned classifier has to beat the zero-shot baseline to justify
existing (see docs/attack-techniques-dataset.md).
"""

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Optional

import numpy as np
import torch
from datasets import load_dataset
from transformers import (
    AutoModel,
    AutoModelForSequenceClassification,
    AutoTokenizer,
)

from vulntrain.datasets.attack_guesser_dataset import (
    ENTERPRISE_ATTACK_STIX_URL,
    download_file,
)
from vulntrain.trainers.attack_guesser import (
    build_label_vocabulary,
    collapse_subtechnique,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

RECALL_KS = (1, 3, 5, 10)


def load_technique_texts(
    stix_path: Path, vocabulary: list[str]
) -> dict[str, str]:
    """Return 'Name. Description' for every vocabulary technique, from the
    enterprise ATT&CK STIX bundle."""
    with open(stix_path, encoding="utf-8") as f:
        bundle = json.load(f)
    texts: dict[str, str] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        external_id = next(
            (
                reference.get("external_id")
                for reference in obj.get("external_references", [])
                if reference.get("source_name") == "mitre-attack"
            ),
            None,
        )
        if external_id in vocabulary:
            name = obj.get("name", "")
            description = obj.get("description", "")
            texts[external_id] = f"{name}. {description}".strip()
    missing = set(vocabulary) - set(texts)
    if missing:
        logger.warning(f"No STIX text found for techniques: {sorted(missing)}")
    return texts


def embed_texts(
    texts: list[str],
    tokenizer: Any,
    model: Any,
    batch_size: int,
    max_length: int = 512,
) -> torch.Tensor:
    """Mean-pooled, L2-normalized sentence embeddings."""
    model.eval()
    embeddings = []
    for start in range(0, len(texts), batch_size):
        batch = tokenizer(
            texts[start : start + batch_size],
            padding=True,
            truncation=True,
            max_length=max_length,
            return_tensors="pt",
        )
        with torch.no_grad():
            output = model(**batch)
        hidden = output.last_hidden_state
        mask = batch["attention_mask"].unsqueeze(-1).float()
        pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)
        embeddings.append(torch.nn.functional.normalize(pooled, dim=1))
    return torch.cat(embeddings)


def ranking_metrics(
    ranked_labels: list[list[str]], gold_sets: list[set[str]]
) -> dict[str, float]:
    """recall@k and mean reciprocal rank over ranked technique lists."""
    recalls: dict[int, list[float]] = {k: [] for k in RECALL_KS}
    reciprocal_ranks: list[float] = []
    for ranked, gold in zip(ranked_labels, gold_sets):
        for k in RECALL_KS:
            hits = len(gold & set(ranked[:k]))
            recalls[k].append(hits / len(gold))
        first_hit = next(
            (rank for rank, label in enumerate(ranked, start=1) if label in gold),
            None,
        )
        reciprocal_ranks.append(1.0 / first_hit if first_hit else 0.0)
    metrics = {f"recall_at_{k}": float(np.mean(recalls[k])) for k in RECALL_KS}
    metrics["mrr"] = float(np.mean(reciprocal_ranks))
    return metrics


def prepare_evaluation_data(
    dataset_id: str, split: str, min_examples: int, vocabulary: Optional[list[str]]
) -> tuple[list[str], list[str], list[set[str]], list[str]]:
    """Return (texts, ids, gold technique sets, vocabulary) for evaluation.

    Gold sub-techniques are collapsed to parents and restricted to the
    vocabulary; examples with no in-vocabulary technique are skipped, exactly
    like the trainer does.
    """
    dataset = load_dataset(dataset_id)
    if vocabulary is None:
        vocabulary = build_label_vocabulary(
            dataset["train"]["techniques"], min_examples, keep_subtechniques=False
        )
    vocabulary_set = set(vocabulary)

    texts: list[str] = []
    vuln_ids: list[str] = []
    gold_sets: list[set[str]] = []
    skipped = 0
    for example in dataset[split]:
        gold = {
            collapse_subtechnique(technique) for technique in example["techniques"]
        } & vocabulary_set
        if not gold:
            skipped += 1
            continue
        texts.append(f"{example['title']}\n{example['description']}".strip())
        vuln_ids.append(example["id"])
        gold_sets.append(gold)
    logger.info(
        f"Evaluating on {len(texts)} {split} examples "
        f"({skipped} skipped: no in-vocabulary technique), "
        f"{len(vocabulary)} candidate techniques"
    )
    return texts, vuln_ids, gold_sets, vocabulary


def evaluate_similarity(args: argparse.Namespace) -> dict[str, float]:
    texts, _, gold_sets, vocabulary = prepare_evaluation_data(
        args.dataset_id, args.split, args.min_examples, vocabulary=None
    )

    cache_dir = Path(args.cache_dir).expanduser()
    stix_path = download_file(
        ENTERPRISE_ATTACK_STIX_URL, cache_dir, "enterprise-attack.json"
    )
    technique_texts = load_technique_texts(stix_path, vocabulary)
    candidate_labels = sorted(technique_texts)

    logger.info(f"Embedding with {args.embedding_model}")
    tokenizer = AutoTokenizer.from_pretrained(args.embedding_model)
    model = AutoModel.from_pretrained(args.embedding_model)

    technique_embeddings = embed_texts(
        [technique_texts[label] for label in candidate_labels],
        tokenizer,
        model,
        args.batch_size,
    )
    description_embeddings = embed_texts(texts, tokenizer, model, args.batch_size)

    similarities = description_embeddings @ technique_embeddings.T
    ranked_indices = torch.argsort(similarities, dim=1, descending=True).numpy()
    ranked_labels = [
        [candidate_labels[index] for index in row] for row in ranked_indices
    ]
    return ranking_metrics(ranked_labels, gold_sets)


def evaluate_classifier(args: argparse.Namespace) -> dict[str, float]:
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(args.model)
    model.eval()

    # The model's own label vocabulary guarantees a fair comparison with the
    # training-time protocol.
    id_to_label = model.config.id2label
    vocabulary = [id_to_label[index] for index in sorted(id_to_label)]

    texts, _, gold_sets, _ = prepare_evaluation_data(
        args.dataset_id, args.split, args.min_examples, vocabulary=vocabulary
    )

    all_logits = []
    for start in range(0, len(texts), args.batch_size):
        batch = tokenizer(
            texts[start : start + args.batch_size],
            padding=True,
            truncation=True,
            max_length=512,
            return_tensors="pt",
        )
        with torch.no_grad():
            output = model(**batch)
        all_logits.append(output.logits)
    logits = torch.cat(all_logits)

    ranked_indices = torch.argsort(logits, dim=1, descending=True).numpy()
    ranked_labels = [
        [vocabulary[index] for index in row] for row in ranked_indices
    ]
    metrics = ranking_metrics(ranked_labels, gold_sets)

    # Threshold metrics, as reported during training.
    predictions = (logits.numpy() >= 0.0).astype(int)
    gold_matrix = np.zeros_like(predictions)
    label_to_id = {label: index for index, label in enumerate(vocabulary)}
    for row, gold in enumerate(gold_sets):
        for label in gold:
            gold_matrix[row, label_to_id[label]] = 1
    from sklearn.metrics import f1_score

    metrics["f1_micro"] = f1_score(
        gold_matrix, predictions, average="micro", zero_division=0
    )
    metrics["f1_macro"] = f1_score(
        gold_matrix, predictions, average="macro", zero_division=0
    )
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate ATT&CK technique suggestion methods (zero-shot "
        "similarity baseline or fine-tuned classifier) on the same protocol."
    )
    parser.add_argument(
        "--method",
        choices=["similarity", "classifier"],
        default="similarity",
        help="'similarity' for the zero-shot embedding baseline, 'classifier' "
        "for a model trained with vulntrain-train-attack-classification.",
    )
    parser.add_argument(
        "--dataset-id",
        default="CIRCL/vulnerability-attack-techniques",
        help="Evaluation dataset.",
    )
    parser.add_argument(
        "--split",
        default="test",
        help="Dataset split to evaluate on.",
    )
    parser.add_argument(
        "--embedding-model",
        default="sentence-transformers/all-MiniLM-L6-v2",
        help="Sentence encoder for the similarity baseline.",
    )
    parser.add_argument(
        "--model",
        default="",
        help="Fine-tuned classifier repo ID or local path (required with "
        "--method classifier).",
    )
    parser.add_argument(
        "--min-examples",
        type=int,
        default=5,
        help="Vocabulary cutoff, must match the trainer's for a fair "
        "comparison (similarity method only; the classifier brings its own "
        "vocabulary).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=16,
        help="Inference batch size.",
    )
    parser.add_argument(
        "--cache-dir",
        default="~/.cache/vulntrain",
        help="Directory where the ATT&CK STIX data is cached.",
    )
    args = parser.parse_args()

    if args.method == "classifier":
        if not args.model:
            parser.error("--method classifier requires --model")
        metrics = evaluate_classifier(args)
    else:
        metrics = evaluate_similarity(args)

    print(f"\n{'=' * 60}")
    print(f"Method: {args.method}")
    if args.method == "similarity":
        print(f"Embedding model: {args.embedding_model}")
    else:
        print(f"Model: {args.model}")
    for name, value in metrics.items():
        print(f"  {name}: {value:.4f}")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
