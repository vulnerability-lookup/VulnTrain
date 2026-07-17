"""Run a trained ATT&CK technique classifier on a single CVE description.

Companion to vulntrain-train-attack-classification: loads a fine-tuned
multi-label model (local path or Hugging Face repo ID) and prints the
top-k techniques with sigmoid probabilities for one vulnerability
description. The description can be given directly (--description) or
looked up by CVE ID in the gold dataset (--cve), in which case the gold
techniques are printed alongside the predictions for comparison.

Probabilities at or above 0.5 (logit >= 0) are the model's positive
predictions — the same threshold the trainer uses for its F1 metrics;
the remaining rows show how the model ranks the rest of its vocabulary.
"""

import argparse
import json
import logging
from pathlib import Path
from typing import Optional

import torch
from datasets import load_dataset
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from vulntrain.datasets.attack_guesser_dataset import (
    ENTERPRISE_ATTACK_STIX_URL,
    download_file,
)
from vulntrain.trainers.attack_guesser import collapse_subtechnique

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


def load_technique_names(stix_path: Path) -> dict[str, str]:
    """Technique ID -> name from the enterprise ATT&CK STIX bundle."""
    with open(stix_path, encoding="utf-8") as f:
        bundle = json.load(f)
    names: dict[str, str] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        external_id = next(
            (
                reference.get("external_id")
                for reference in obj.get("external_references", [])
                if reference.get("source_name") == "mitre-attack"
            ),
            None,
        )
        if external_id:
            names[external_id] = obj.get("name", "")
    return names


def lookup_cve(dataset_id: str, cve_id: str) -> tuple[str, str, str, set[str]]:
    """Return (split, title, description, collapsed gold techniques) for a
    CVE in the gold dataset, or exit if it is not there."""
    dataset = load_dataset(dataset_id)
    for split in dataset:
        for example in dataset[split]:
            if example["id"] == cve_id:
                gold = {
                    collapse_subtechnique(technique)
                    for technique in example["techniques"]
                }
                return str(split), example["title"], example["description"], gold
    raise SystemExit(
        f"{cve_id} is not in {dataset_id}; pass its text with --description "
        "instead (no gold techniques will be shown)."
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Predict ATT&CK techniques for one CVE description with a "
        "model trained by vulntrain-train-attack-classification."
    )
    parser.add_argument(
        "--model",
        required=True,
        help="Fine-tuned classifier: local path or Hugging Face repo ID.",
    )
    parser.add_argument(
        "--description",
        default="",
        help="Vulnerability description to classify.",
    )
    parser.add_argument(
        "--title",
        default="",
        help="Optional vulnerability title, prepended to the description "
        "exactly as during training.",
    )
    parser.add_argument(
        "--cve",
        default="",
        help="CVE ID to look up in the gold dataset instead of passing "
        "--description; also prints the gold techniques.",
    )
    parser.add_argument(
        "--dataset-id",
        default="CIRCL/vulnerability-attack-techniques",
        help="Gold dataset used for --cve lookups.",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=10,
        help="Number of techniques to print.",
    )
    parser.add_argument(
        "--cache-dir",
        default="~/.cache/vulntrain",
        help="Directory where the ATT&CK STIX data is cached (for technique "
        "names; IDs only if unavailable).",
    )
    args = parser.parse_args()

    if bool(args.cve) == bool(args.description):
        parser.error("pass exactly one of --cve or --description")

    gold: Optional[set[str]] = None
    title, description = args.title, args.description
    header = "ad-hoc description"
    if args.cve:
        split, title, description, gold = lookup_cve(args.dataset_id, args.cve)
        header = f"{args.cve} ({split} split)"

    names: dict[str, str] = {}
    try:
        stix_path = download_file(
            ENTERPRISE_ATTACK_STIX_URL,
            Path(args.cache_dir).expanduser(),
            "enterprise-attack.json",
        )
        names = load_technique_names(stix_path)
    except Exception as exception:
        logger.warning(f"No technique names ({exception}); printing IDs only.")

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(args.model)
    model.eval()
    vocabulary = [
        model.config.id2label[index] for index in sorted(model.config.id2label)
    ]

    text = f"{title}\n{description}".strip()
    batch = tokenizer(
        text, truncation=True, max_length=512, return_tensors="pt"
    )
    with torch.no_grad():
        probabilities = torch.sigmoid(model(**batch).logits[0])
    ranked = torch.argsort(probabilities, descending=True)

    print(f"\n{header} | model: {args.model}")
    if gold is not None:
        in_vocabulary = gold & set(vocabulary)
        print(f"gold techniques: {', '.join(sorted(gold))}")
        if gold - in_vocabulary:
            print(
                "  (not in the model's vocabulary: "
                f"{', '.join(sorted(gold - in_vocabulary))})"
            )
    print(f"{'rank':>4}  {'technique':<10} {'prob':>5}  pred  gold  name")
    for rank, index in enumerate(ranked[: args.top_k].tolist(), start=1):
        technique = vocabulary[index]
        probability = probabilities[index].item()
        predicted = "*" if probability >= 0.5 else " "
        hit = "+" if gold is not None and technique in gold else " "
        print(
            f"{rank:>4}  {technique:<10} {probability:>5.2f}  "
            f"{predicted:^4}  {hit:^4}  {names.get(technique, '')}"
        )


if __name__ == "__main__":
    main()
