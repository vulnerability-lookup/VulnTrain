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

The classifier method can additionally re-rank with the CVE2CAPEC-derived
candidate prior (the dataset's ``techniques_derived`` column, never used
for training): ``--prior boost`` adds ``--prior-alpha`` to the logit of
every technique in a CVE's derived candidate set; ``--prior mask`` is the
limiting case (candidate techniques rank strictly before the rest). Tune
alpha on the validation carve-out (``--split validation``), never on test.
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

from vulntrain.attack_metadata import build_input_text
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
    dataset_id: str,
    split: str,
    min_examples: int,
    vocabulary: Optional[list[str]],
    val_split: float = 0.1,
    val_seed: int = 42,
    metadata_signals: Optional[list[str]] = None,
) -> tuple[
    list[str],
    list[str],
    list[set[str]],
    list[set[str]],
    list[str],
    list[str],
    list[bool],
]:
    """Return (texts, ids, gold sets, derived candidate sets, vocabulary,
    label-source groups, gold-CWE presence flags).

    Texts are built with the same ``build_input_text`` as the trainer,
    appending the given verbalized metadata signals (none by default).
    Gold sub-techniques are collapsed to parents and restricted to the
    vocabulary; examples with no in-vocabulary technique are skipped, exactly
    like the trainer does. The derived sets are the CVE2CAPEC
    ``techniques_derived`` candidates, collapsed to parents (NOT restricted
    to the vocabulary — the restriction happens where they are used).

    ``split="validation"`` reconstructs the trainer's checkpoint-selection
    carve-out (train_test_split of the train split with ``val_split`` and
    ``val_seed``), so prior hyper-parameters can be tuned without touching
    the test split.
    """
    dataset = load_dataset(dataset_id)
    if vocabulary is None:
        vocabulary = build_label_vocabulary(
            dataset["train"]["techniques"], min_examples, keep_subtechniques=False
        )
    vocabulary_set = set(vocabulary)

    if split == "validation" and "validation" not in dataset:
        carve = dataset["train"].train_test_split(test_size=val_split, seed=val_seed)
        examples = carve["test"]
        logger.info(
            f"Reconstructed the validation carve-out from train "
            f"(val_split={val_split}, seed={val_seed}): {len(examples)} examples"
        )
    else:
        examples = dataset[split]

    texts: list[str] = []
    vuln_ids: list[str] = []
    gold_sets: list[set[str]] = []
    derived_sets: list[set[str]] = []
    source_groups: list[str] = []
    cwe_flags: list[bool] = []
    skipped = 0
    for example in examples:
        gold = {
            collapse_subtechnique(technique) for technique in example["techniques"]
        } & vocabulary_set
        if not gold:
            skipped += 1
            continue
        texts.append(build_input_text(example, metadata_signals or []))
        vuln_ids.append(example["id"])
        gold_sets.append(gold)
        derived_sets.append(
            {
                collapse_subtechnique(technique)
                for technique in example.get("techniques_derived") or []
            }
        )
        source_groups.append("+".join(sorted(example.get("label_sources") or [])))
        cwe_flags.append(bool(example.get("cwes")))
    logger.info(
        f"Evaluating on {len(texts)} {split} examples "
        f"({skipped} skipped: no in-vocabulary technique), "
        f"{len(vocabulary)} candidate techniques"
    )
    return (
        texts,
        vuln_ids,
        gold_sets,
        derived_sets,
        vocabulary,
        source_groups,
        cwe_flags,
    )


def candidate_prior_diagnostics(
    gold_sets: list[set[str]], derived_sets: list[set[str]], vocabulary_set: set[str]
) -> None:
    """Log how informative the CVE2CAPEC candidate sets are on this split."""
    in_vocab = [derived & vocabulary_set for derived in derived_sets]
    non_empty = sum(1 for candidates in in_vocab if candidates)
    sizes = [len(candidates) for candidates in in_vocab if candidates]
    coverages = [
        len(gold & candidates) / len(gold)
        for gold, candidates in zip(gold_sets, in_vocab)
    ]
    logger.info(
        f"Derived prior: {non_empty}/{len(derived_sets)} examples with "
        f"in-vocabulary candidates; candidate-set size "
        f"mean={np.mean(sizes):.1f} median={np.median(sizes):.0f}"
        if sizes
        else "Derived prior: no in-vocabulary candidates on this split"
    )
    logger.info(
        f"Derived prior: candidate sets cover {np.mean(coverages):.3f} of the "
        f"gold techniques on average (the ceiling of the mask variant)"
    )


def fuse_with_prior(
    logits: np.ndarray,
    derived_sets: list[set[str]],
    vocabulary: list[str],
    alpha: float,
) -> np.ndarray:
    """score = logit + alpha * 1[technique in the CVE's derived candidates]."""
    label_to_id = {label: index for index, label in enumerate(vocabulary)}
    member = np.zeros_like(logits)
    for row, derived in enumerate(derived_sets):
        for label in derived:
            if label in label_to_id:
                member[row, label_to_id[label]] = 1.0
    return logits + alpha * member


def evaluate_similarity(args: argparse.Namespace) -> dict[str, float]:
    texts, _, gold_sets, _, vocabulary, _, _ = prepare_evaluation_data(
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


MASK_ALPHA = 1e6  # far above any logit magnitude: candidates rank strictly first


def rank_and_score(
    scores: np.ndarray, vocabulary: list[str], gold_sets: list[set[str]]
) -> dict[str, float]:
    ranked_indices = np.argsort(scores, axis=1)[:, ::-1]
    ranked_labels = [[vocabulary[index] for index in row] for row in ranked_indices]
    return ranking_metrics(ranked_labels, gold_sets)


def threshold_f1(
    logits: np.ndarray, vocabulary: list[str], gold_sets: list[set[str]]
) -> dict[str, float]:
    """Micro/macro F1 at the training-time decision threshold (logit >= 0,
    i.e. probability 0.5). Raw logits only: the threshold is meaningless on
    prior-shifted scores. Macro-F1 averages over the full vocabulary, so on
    a small subset labels absent from it contribute 0 — compare subsets only
    against the same subset under another model, never against the full set.
    """
    from sklearn.metrics import f1_score

    predictions = (logits >= 0.0).astype(int)
    gold_matrix = np.zeros_like(predictions)
    label_to_id = {label: index for index, label in enumerate(vocabulary)}
    for row, gold in enumerate(gold_sets):
        for label in gold:
            gold_matrix[row, label_to_id[label]] = 1
    return {
        "f1_micro": float(
            f1_score(gold_matrix, predictions, average="micro", zero_division=0)
        ),
        "f1_macro": float(
            f1_score(gold_matrix, predictions, average="macro", zero_division=0)
        ),
    }


def evaluate_classifier(args: argparse.Namespace) -> dict[str, dict[str, float]]:
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(args.model)
    model.eval()

    # The model's own label vocabulary guarantees a fair comparison with the
    # training-time protocol.
    id_to_label = model.config.id2label
    vocabulary = [id_to_label[index] for index in sorted(id_to_label)]

    # Build inputs exactly as the model was trained (recorded by the trainer).
    metadata_signals = list(getattr(model.config, "metadata_inputs", []) or [])
    if metadata_signals:
        logger.info(f"Model was trained with metadata inputs: {metadata_signals}")

    texts, _, gold_sets, derived_sets, _, source_groups, cwe_flags = (
        prepare_evaluation_data(
            args.dataset_id,
            args.split,
            args.min_examples,
            vocabulary=vocabulary,
            metadata_signals=metadata_signals,
        )
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
    logits = torch.cat(all_logits).numpy()

    metrics = rank_and_score(logits, vocabulary, gold_sets)
    metrics.update(threshold_f1(logits, vocabulary, gold_sets))
    results = {"classifier": metrics}

    if args.stratify:
        # Cross-strata: per label_sources group, per gold-CWE presence, and
        # their intersection. The intersection separates coverage dilution
        # (CWE helps wherever it is present) from stratum-level effects
        # (e.g. curated KEV assignments) — empty strata are simply absent.
        strata: dict[str, list[int]] = {}
        for index, (group, has_cwe) in enumerate(zip(source_groups, cwe_flags)):
            presence = "cwe-present" if has_cwe else "cwe-absent"
            for name in (group, presence, f"{group}/{presence}"):
                strata.setdefault(name, []).append(index)
        for name in sorted(strata):
            indices = strata[name]
            group_gold = [gold_sets[index] for index in indices]
            group_metrics = rank_and_score(logits[indices], vocabulary, group_gold)
            group_metrics.update(
                threshold_f1(logits[indices], vocabulary, group_gold)
            )
            group_metrics["n_examples"] = float(len(indices))
            results[f"classifier[{name}]"] = group_metrics

    if args.prior != "none":
        candidate_prior_diagnostics(gold_sets, derived_sets, set(vocabulary))
        alphas = [MASK_ALPHA] if args.prior == "mask" else args.prior_alpha
        for alpha in alphas:
            fused = fuse_with_prior(logits, derived_sets, vocabulary, alpha)
            name = "mask" if args.prior == "mask" else f"boost(alpha={alpha:g})"
            results[name] = rank_and_score(fused, vocabulary, gold_sets)
    return results


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
        help="Dataset split to evaluate on. 'validation' reconstructs the "
        "trainer's checkpoint-selection carve-out (val_split 0.1, seed 42) "
        "for tuning prior hyper-parameters without touching the test split.",
    )
    parser.add_argument(
        "--prior",
        choices=["none", "boost", "mask"],
        default="none",
        help="Re-rank classifier scores with the CVE2CAPEC-derived candidate "
        "prior (techniques_derived): 'boost' adds --prior-alpha to candidate "
        "logits, 'mask' ranks candidates strictly first (the alpha->inf "
        "limit). Classifier method only.",
    )
    parser.add_argument(
        "--prior-alpha",
        dest="prior_alpha",
        type=float,
        nargs="+",
        default=[1.0],
        help="Boost value(s) added to candidate logits; pass several to sweep "
        "(tune on --split validation, then run the chosen value on test once).",
    )
    parser.add_argument(
        "--stratify",
        action="store_true",
        help="Additionally report metrics per label_sources group, per "
        "gold-CWE presence, and their intersection (e.g. ctid_cve, "
        "cwe-present, ctid_cve/cwe-present) to expose metadata-coverage "
        "confounds. Classifier method only.",
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
        results = evaluate_classifier(args)
    else:
        if args.prior != "none":
            parser.error("--prior requires --method classifier")
        if args.stratify:
            parser.error("--stratify requires --method classifier")
        results = {"similarity": evaluate_similarity(args)}

    print(f"\n{'=' * 60}")
    print(f"Method: {args.method}  (split: {args.split})")
    if args.method == "similarity":
        print(f"Embedding model: {args.embedding_model}")
    else:
        print(f"Model: {args.model}")
    for config, metrics in results.items():
        print(f"[{config}]")
        for name, value in metrics.items():
            print(f"  {name}: {value:.4f}")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
