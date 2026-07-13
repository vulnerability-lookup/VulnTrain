"""LLM-assisted expansion of the CVE -> MITRE ATT&CK techniques dataset
(Phase 2).

The hand-curated CTID gold set (see docs/attack-techniques-dataset.md) covers
only ~1,200 CVEs. This script uses Claude to label additional CVEs following
the same "Mapping ATT&CK to CVE for Impact" methodology, so the labels stay
schema-compatible with the gold set.

Two modes, and you must run them in order:

- ``validate``: label a held-out slice of the *gold* set and measure agreement
  (precision/recall/F1) between the model and the analysts. This is the gate —
  do not trust expansion until the agreement is acceptable.
- ``expand``: label a sample of unlabeled CVEs and write a dataset with
  ``label_source = ["llm"]``. Merge with the gold set downstream, keeping the
  provenance column so consumers can always filter back to gold-only.

Requires Anthropic API credentials (``ANTHROPIC_API_KEY`` or an ``ant auth
login`` profile) — the labeling itself is not run in CI.
"""

import argparse
import json
import logging
import time
from pathlib import Path
from typing import Any, Optional

from datasets import Dataset, DatasetDict, load_dataset
from pydantic import BaseModel, Field

from vulntrain.datasets.attack_guesser_dataset import (
    ENTERPRISE_ATTACK_STIX_URL,
    TECHNIQUE_RE,
    download_file,
)
from vulntrain.trainers.attack_guesser import collapse_subtechnique

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-opus-4-8"

METHODOLOGY = """\
You map software vulnerabilities (CVEs) to MITRE ATT&CK (Enterprise) techniques \
following the MITRE Center for Threat-Informed Defense "Mapping ATT&CK to CVE \
for Impact" methodology. For each CVE description, assign techniques to up to \
three slots:

- exploitation_technique: how an adversary exploits the vulnerability to gain \
initial access or execution (e.g. T1190 Exploit Public-Facing Application, \
T1203 Exploitation for Client Execution, T1068 Exploitation for Privilege \
Escalation).
- primary_impact: what the exploitation directly yields (e.g. T1059 Command \
and Scripting Interpreter, T1005 Data from Local System, T1499 Endpoint Denial \
of Service).
- secondary_impact: what the adversary can plausibly do next as a direct \
consequence, if clearly implied by the description.

Rules:
- Use ONLY technique IDs from the catalog below. Never invent an ID.
- Prefer the most specific technique the description supports; use a sub-technique \
(e.g. T1059.001) only when the description clearly warrants it.
- Assign a technique only when the description supports it. Leave a slot empty \
rather than guessing. Most CVEs have one exploitation technique and one primary \
impact; secondary impact is often empty.
- Base the mapping strictly on the described behavior of the flaw, not on \
speculation about a full attack chain.
"""


class AttackLabels(BaseModel):
    """Structured ATT&CK mapping for one CVE."""

    comment: str = Field(
        description="One sentence justifying the mapping, citing the described behavior."
    )
    exploitation_techniques: list[str] = Field(
        default_factory=list, description="ATT&CK technique IDs, e.g. ['T1190']."
    )
    primary_impact: list[str] = Field(
        default_factory=list, description="ATT&CK technique IDs, e.g. ['T1059']."
    )
    secondary_impact: list[str] = Field(
        default_factory=list, description="ATT&CK technique IDs, possibly empty."
    )


def load_technique_catalog(cache_dir: Path) -> dict[str, str]:
    """id -> name for every active enterprise ATT&CK technique."""
    stix_path = download_file(
        ENTERPRISE_ATTACK_STIX_URL, cache_dir, "enterprise-attack.json"
    )
    with open(stix_path, encoding="utf-8") as f:
        bundle = json.load(f)
    catalog: dict[str, str] = {}
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
        if external_id and TECHNIQUE_RE.fullmatch(external_id):
            catalog[external_id] = obj.get("name", "")
    logger.info(f"Loaded {len(catalog)} active enterprise ATT&CK techniques")
    return catalog


def format_catalog(catalog: dict[str, str]) -> str:
    return "\n".join(f"{tid} {name}" for tid, name in sorted(catalog.items()))


def format_few_shot(examples: list[dict[str, Any]]) -> str:
    blocks = []
    for example in examples:
        labels = {
            "exploitation_techniques": example["exploitation_techniques"],
            "primary_impact": example["primary_impact"],
            "secondary_impact": example["secondary_impact"],
        }
        blocks.append(
            f"CVE: {example['id']}\n"
            f"Description: {example['description']}\n"
            f"Mapping: {json.dumps(labels)}"
        )
    return "\n\n".join(blocks)


def build_system_blocks(
    catalog: dict[str, str], few_shot: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """System prompt as a single cacheable block: methodology, the full
    technique catalog, and few-shot gold examples. Identical across every CVE,
    so prompt caching makes all but the first request cheap."""
    text = (
        f"{METHODOLOGY}\n\n"
        f"ATT&CK technique catalog (id name):\n{format_catalog(catalog)}\n\n"
        f"Worked examples from analyst-curated mappings:\n"
        f"{format_few_shot(few_shot)}"
    )
    return [{"type": "text", "text": text, "cache_control": {"type": "ephemeral"}}]


def clean_techniques(
    raw: list[str], catalog: dict[str, str]
) -> tuple[list[str], list[str]]:
    """Keep only well-formed IDs present in the catalog; return (kept, dropped)."""
    kept, dropped = [], []
    for technique in raw:
        technique = (technique or "").strip().upper()
        if TECHNIQUE_RE.fullmatch(technique) and technique in catalog:
            kept.append(technique)
        else:
            dropped.append(technique)
    return kept, dropped


def label_cve(
    client: Any,
    system_blocks: list[dict[str, Any]],
    title: str,
    description: str,
    catalog: dict[str, str],
    model: str,
) -> Optional[dict[str, Any]]:
    """Label one CVE. Returns None on a safety refusal (logged and skipped)."""
    user_text = f"{title}\n{description}".strip()
    response = client.messages.parse(
        model=model,
        max_tokens=4000,
        thinking={"type": "adaptive"},
        system=system_blocks,
        messages=[{"role": "user", "content": user_text}],
        output_format=AttackLabels,
    )
    if getattr(response, "stop_reason", None) == "refusal":
        logger.warning("Model refused to label a CVE; skipping")
        return None

    labels: AttackLabels = response.parsed_output
    result: dict[str, Any] = {}
    all_dropped: list[str] = []
    for slot in ("exploitation_techniques", "primary_impact", "secondary_impact"):
        kept, dropped = clean_techniques(getattr(labels, slot), catalog)
        result[slot] = kept
        all_dropped.extend(dropped)
    if all_dropped:
        logger.warning(f"Dropped out-of-catalog technique IDs: {all_dropped}")
    result["comment"] = labels.comment
    result["techniques"] = sorted(
        set(
            result["exploitation_techniques"]
            + result["primary_impact"]
            + result["secondary_impact"]
        )
    )
    return result


def parent_set(techniques: list[str]) -> set[str]:
    return {collapse_subtechnique(t) for t in techniques}


def score_agreement(
    predictions: list[list[str]], gold: list[list[str]]
) -> dict[str, float]:
    """Micro/macro precision, recall, F1 of predicted vs gold parent techniques."""
    tp = fp = fn = 0
    per_label_f1: list[float] = []
    for predicted, truth in zip(predictions, gold):
        p, g = parent_set(predicted), parent_set(truth)
        tp += len(p & g)
        fp += len(p - g)
        fn += len(g - p)
        if p or g:
            precision = len(p & g) / len(p) if p else 0.0
            recall = len(p & g) / len(g) if g else 0.0
            f1 = (
                2 * precision * recall / (precision + recall)
                if precision + recall
                else 0.0
            )
            per_label_f1.append(f1)
    precision_micro = tp / (tp + fp) if tp + fp else 0.0
    recall_micro = tp / (tp + fn) if tp + fn else 0.0
    f1_micro = (
        2 * precision_micro * recall_micro / (precision_micro + recall_micro)
        if precision_micro + recall_micro
        else 0.0
    )
    return {
        "precision_micro": precision_micro,
        "recall_micro": recall_micro,
        "f1_micro": f1_micro,
        "f1_per_cve_mean": sum(per_label_f1) / len(per_label_f1)
        if per_label_f1
        else 0.0,
    }


def select_few_shot(
    train_rows: list[dict[str, Any]], exclude_ids: set[str], count: int
) -> list[dict[str, Any]]:
    """Diverse few-shot examples: greedily cover distinct exploitation techniques."""
    seen_exploitation: set[tuple[str, ...]] = set()
    chosen: list[dict[str, Any]] = []
    for row in train_rows:
        if row["id"] in exclude_ids or not row["description"]:
            continue
        signature = tuple(sorted(row["exploitation_techniques"]))
        if signature and signature in seen_exploitation:
            continue
        seen_exploitation.add(signature)
        chosen.append(row)
        if len(chosen) >= count:
            break
    return chosen


def run_validate(args: argparse.Namespace, client: Any, catalog: dict[str, str]) -> None:
    dataset = load_dataset(args.gold_dataset)
    held_out = list(dataset[args.validate_split])
    if args.limit:
        held_out = held_out[: args.limit]
    held_out_ids = {row["id"] for row in held_out}
    few_shot = select_few_shot(
        list(dataset["train"]), held_out_ids, args.few_shot
    )
    system_blocks = build_system_blocks(catalog, few_shot)
    logger.info(
        f"Validating on {len(held_out)} gold CVEs from the "
        f"'{args.validate_split}' split, {len(few_shot)} few-shot examples"
    )

    predictions: list[list[str]] = []
    gold: list[list[str]] = []
    for i, row in enumerate(held_out, start=1):
        result = label_cve(
            client, system_blocks, row["title"], row["description"], catalog, args.model
        )
        predictions.append(result["techniques"] if result else [])
        gold.append(row["techniques"])
        if i % 10 == 0:
            logger.info(f"Labeled {i}/{len(held_out)}")

    metrics = score_agreement(predictions, gold)
    print(f"\n{'=' * 60}")
    print(f"LLM-vs-gold agreement ({args.model}) on {len(held_out)} CVEs")
    print("(parent-technique level, matching the trainer's granularity)")
    for name, value in metrics.items():
        print(f"  {name}: {value:.4f}")
    print(f"{'=' * 60}\n")
    print(
        "Guidance: only trust `expand` output if this agreement is comparable "
        "to inter-analyst agreement on ATT&CK mappings. Record the number on "
        "the expanded dataset card."
    )


def run_expand(args: argparse.Namespace, client: Any, catalog: dict[str, str]) -> None:
    gold = load_dataset(args.gold_dataset)
    gold_ids = {row for split in gold.values() for row in split["id"]}
    few_shot = select_few_shot(list(gold["train"]), set(), args.few_shot)
    system_blocks = build_system_blocks(catalog, few_shot)

    if args.input_ids_file:
        target_ids = [
            line.strip()
            for line in Path(args.input_ids_file).read_text().splitlines()
            if line.strip().startswith("CVE-")
        ]
    else:
        source = load_dataset(args.description_dataset, split="train")
        target_ids = [
            vid
            for vid in source["id"]
            if vid.startswith("CVE-") and vid not in gold_ids
        ][: args.sample_n]
    logger.info(f"Expanding: labeling {len(target_ids)} CVEs")

    descriptions = _load_descriptions(args.description_dataset, set(target_ids))
    rows = []
    for i, cve_id in enumerate(target_ids, start=1):
        if cve_id not in descriptions:
            continue
        title, description = descriptions[cve_id]
        result = label_cve(client, system_blocks, title, description, catalog, args.model)
        if not result or not result["techniques"]:
            continue
        rows.append(
            {
                "id": cve_id,
                "title": title,
                "description": description,
                "exploitation_techniques": result["exploitation_techniques"],
                "primary_impact": result["primary_impact"],
                "secondary_impact": result["secondary_impact"],
                "techniques": result["techniques"],
                "techniques_derived": [],
                "label_sources": ["llm"],
                "attack_version": args.attack_version,
                "llm_model": args.model,
                "llm_comment": result["comment"],
            }
        )
        if i % 25 == 0:
            logger.info(f"Labeled {i}/{len(target_ids)} ({len(rows)} kept)")
        if args.request_delay:
            time.sleep(args.request_delay)

    logger.info(f"Kept {len(rows)} labeled CVEs")
    dataset = DatasetDict({"train": Dataset.from_list(rows)})
    if args.output_dir:
        dataset.save_to_disk(args.output_dir)
        logger.info(f"Saved to {args.output_dir}")
    if args.push:
        dataset.push_to_hub(
            args.repo_id,
            commit_message=f"[DATASET] LLM-labeled CVE->ATT&CK ({len(rows)} CVEs, {args.model})",
            private=False,
        )
        logger.info(f"Pushed to {args.repo_id}")


def _load_descriptions(
    dataset_id: str, cve_ids: set[str]
) -> dict[str, tuple[str, str]]:
    dataset = load_dataset(dataset_id)
    found: dict[str, tuple[str, str]] = {}
    for split in dataset.values():
        indices = [i for i, vid in enumerate(split["id"]) if vid in cve_ids]
        for row in split.select(indices):
            found.setdefault(
                row["id"], (row.get("title") or "", row.get("description") or "")
            )
    return found


def main() -> None:
    parser = argparse.ArgumentParser(
        description="LLM-assisted expansion of the CVE -> ATT&CK techniques dataset."
    )
    parser.add_argument(
        "--mode",
        choices=["validate", "expand"],
        required=True,
        help="'validate' measures agreement vs the gold set (run first); "
        "'expand' labels new CVEs.",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help="Anthropic model ID used for labeling.",
    )
    parser.add_argument(
        "--gold-dataset",
        default="CIRCL/vulnerability-attack-techniques",
        help="Curated gold dataset (few-shot source and validation target).",
    )
    parser.add_argument(
        "--description-dataset",
        default="CIRCL/vulnerability-scores",
        help="Dataset providing CVE descriptions for expansion.",
    )
    parser.add_argument(
        "--validate-split",
        default="test",
        help="Gold split to score agreement on (validate mode).",
    )
    parser.add_argument(
        "--few-shot",
        type=int,
        default=8,
        help="Number of gold examples to include in the prompt.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Cap the number of CVEs (validate mode); 0 = all.",
    )
    parser.add_argument(
        "--sample-n",
        type=int,
        default=200,
        help="Number of CVEs to label from the description dataset (expand mode).",
    )
    parser.add_argument(
        "--input-ids-file",
        default="",
        help="Optional file of CVE IDs (one per line) to label instead of sampling.",
    )
    parser.add_argument(
        "--attack-version",
        default="19.1",
        help="ATT&CK version tag recorded on expanded rows (match the gold set).",
    )
    parser.add_argument(
        "--cache-dir",
        default="~/.cache/vulntrain",
        help="Directory where the ATT&CK STIX data is cached.",
    )
    parser.add_argument(
        "--request-delay",
        type=float,
        default=0.0,
        help="Seconds to sleep between requests (expand mode rate limiting).",
    )
    parser.add_argument(
        "--output-dir",
        default="",
        help="Local directory to save the expanded dataset (expand mode).",
    )
    parser.add_argument(
        "--repo-id",
        default="CIRCL/vulnerability-attack-techniques-llm",
        help="Hub repo ID for the expanded dataset (expand mode).",
    )
    parser.add_argument(
        "--push",
        action="store_true",
        help="Push the expanded dataset to the Hub (expand mode).",
    )
    args = parser.parse_args()

    import anthropic

    client = anthropic.Anthropic()
    catalog = load_technique_catalog(Path(args.cache_dir).expanduser())

    if args.mode == "validate":
        run_validate(args, client, catalog)
    else:
        run_expand(args, client, catalog)


if __name__ == "__main__":
    main()
