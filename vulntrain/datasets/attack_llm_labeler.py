"""LLM-assisted expansion of the CVE -> MITRE ATT&CK techniques dataset
(Phase 2).

The hand-curated CTID gold set (see docs/attack-techniques-dataset.md) covers
only ~1,200 CVEs. This script uses an LLM to label additional CVEs following
the same "Mapping ATT&CK to CVE for Impact" methodology, so the labels stay
schema-compatible with the gold set.

Two backends:

- ``anthropic``: Claude via the Anthropic API (requires ``ANTHROPIC_API_KEY``).
- ``ollama``: any local model served by an Ollama instance (e.g. Qwen), using
  Ollama structured outputs — no API key or per-token cost.

Two modes, and you must run them in order:

- ``validate``: label a held-out slice of the *gold* set and measure agreement
  (precision/recall/F1) between the model and the analysts. This is the gate —
  do not trust expansion until the agreement is acceptable. Run it once per
  backend/model you consider.
- ``expand``: label a sample of unlabeled CVEs and write a dataset with
  ``label_source = ["llm"]``. Merge with the gold set downstream, keeping the
  provenance column so consumers can always filter back to gold-only.
"""

import argparse
import json
import logging
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

from datasets import Dataset, DatasetDict, load_dataset
from pydantic import BaseModel, Field, ValidationError

from vulntrain.datasets.attack_guesser_dataset import (
    ENTERPRISE_ATTACK_STIX_URL,
    TECHNIQUE_RE,
    download_file,
)
from vulntrain.trainers.attack_guesser import collapse_subtechnique

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DEFAULT_MODELS = {
    "anthropic": "claude-opus-4-8",
    "ollama": "qwen3",
}

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


# ---------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------


class AnthropicBackend:
    """Label CVEs with Claude via the Anthropic API.

    The system prompt is sent as a single cacheable block, so prompt caching
    makes all but the first request cheap.
    """

    def __init__(self, model: str, system_text: str):
        try:
            import anthropic
        except ImportError as e:
            raise SystemExit(
                "The 'anthropic' backend requires the anthropic SDK. Install it "
                "with `poetry install --extras anthropic`, or use "
                "`--backend ollama` for a local model."
            ) from e

        self.client = anthropic.Anthropic()
        self.model = model
        self.system_blocks = [
            {
                "type": "text",
                "text": system_text,
                "cache_control": {"type": "ephemeral"},
            }
        ]

    def label(self, user_text: str) -> Optional[AttackLabels]:
        response = self.client.messages.parse(
            model=self.model,
            max_tokens=4000,
            thinking={"type": "adaptive"},
            system=self.system_blocks,
            messages=[{"role": "user", "content": user_text}],
            output_format=AttackLabels,
        )
        if getattr(response, "stop_reason", None) == "refusal":
            logger.warning("Model refused to label a CVE; skipping")
            return None
        labels: AttackLabels = response.parsed_output
        return labels


def _read_ollama_error(error: urllib.error.HTTPError) -> str:
    """Extract Ollama's JSON error message from an HTTPError body."""
    try:
        body = json.loads(error.read().decode("utf-8"))
        return str(body.get("error", body))
    except (ValueError, OSError):
        return error.reason if isinstance(error.reason, str) else str(error)


class OllamaBackend:
    """Label CVEs with a local model served by Ollama (no API key needed).

    Uses Ollama structured outputs: the JSON schema of AttackLabels is passed
    as the ``format`` parameter, constraining the model's output. Ollama's
    prompt prefix caching keeps the repeated system prompt cheap across
    consecutive requests.
    """

    MAX_ATTEMPTS = 3

    def __init__(self, model: str, system_text: str, base_url: str, timeout: int):
        self.model = model
        self.system_text = system_text
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def label(self, user_text: str) -> Optional[AttackLabels]:
        payload = json.dumps(
            {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": self.system_text},
                    {"role": "user", "content": user_text},
                ],
                "format": AttackLabels.model_json_schema(),
                "stream": False,
                "options": {"temperature": 0},
            }
        ).encode("utf-8")

        for attempt in range(1, self.MAX_ATTEMPTS + 1):
            request = urllib.request.Request(
                f"{self.base_url}/api/chat",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                    data = json.load(resp)
                content = data.get("message", {}).get("content", "")
                return AttackLabels.model_validate_json(content)
            except urllib.error.HTTPError as e:
                # 4xx are configuration errors (model not pulled, bad request)
                # — the same call will fail for every CVE, so fail fast with
                # Ollama's own message rather than retrying.
                detail = _read_ollama_error(e)
                if 400 <= e.code < 500:
                    raise SystemExit(
                        f"Ollama returned HTTP {e.code} for model "
                        f"'{self.model}': {detail}\n"
                        f"Check the model is pulled (`ollama list`; "
                        f"`ollama pull {self.model}`) and reachable at "
                        f"{self.base_url}."
                    ) from e
                logger.warning(
                    f"[{attempt}/{self.MAX_ATTEMPTS}] Ollama HTTP {e.code}: {detail}"
                )
                time.sleep(2**attempt)
            except (ValidationError, json.JSONDecodeError) as e:
                logger.warning(
                    f"[{attempt}/{self.MAX_ATTEMPTS}] Model returned invalid "
                    f"structured output: {e}"
                )
            except (urllib.error.URLError, TimeoutError) as e:
                logger.warning(
                    f"[{attempt}/{self.MAX_ATTEMPTS}] Ollama request failed: {e}"
                )
                time.sleep(2**attempt)
        return None


def make_backend(args: argparse.Namespace, system_text: str) -> Any:
    if args.backend == "ollama":
        return OllamaBackend(
            args.model, system_text, args.ollama_url, args.ollama_timeout
        )
    return AnthropicBackend(args.model, system_text)


# ---------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------


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


def build_system_text(
    catalog: dict[str, str], few_shot: list[dict[str, Any]]
) -> str:
    """System prompt shared by all backends: methodology, the full technique
    catalog, and few-shot gold examples. Identical across every CVE."""
    return (
        f"{METHODOLOGY}\n\n"
        f"ATT&CK technique catalog (id name):\n{format_catalog(catalog)}\n\n"
        f"Worked examples from analyst-curated mappings:\n"
        f"{format_few_shot(few_shot)}"
    )


# ---------------------------------------------------------------------
# Labeling and scoring
# ---------------------------------------------------------------------


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
    backend: Any,
    title: str,
    description: str,
    catalog: dict[str, str],
) -> Optional[dict[str, Any]]:
    """Label one CVE. Returns None when the backend produced no usable labels."""
    labels = backend.label(f"{title}\n{description}".strip())
    if labels is None:
        return None

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


# ---------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------


def run_validate(
    args: argparse.Namespace, catalog: dict[str, str]
) -> None:
    dataset = load_dataset(args.gold_dataset)
    held_out = list(dataset[args.validate_split])
    if args.limit:
        held_out = held_out[: args.limit]
    held_out_ids = {row["id"] for row in held_out}
    few_shot = select_few_shot(list(dataset["train"]), held_out_ids, args.few_shot)
    backend = make_backend(args, build_system_text(catalog, few_shot))
    logger.info(
        f"Validating {args.backend}/{args.model} on {len(held_out)} gold CVEs "
        f"from the '{args.validate_split}' split, {len(few_shot)} few-shot examples"
    )

    predictions: list[list[str]] = []
    gold: list[list[str]] = []
    failures = 0
    for i, row in enumerate(held_out, start=1):
        result = label_cve(backend, row["title"], row["description"], catalog)
        if result is None:
            failures += 1
        predictions.append(result["techniques"] if result else [])
        gold.append(row["techniques"])
        if i % 10 == 0:
            logger.info(f"Labeled {i}/{len(held_out)}")

    metrics = score_agreement(predictions, gold)
    print(f"\n{'=' * 60}")
    print(
        f"LLM-vs-gold agreement ({args.backend}/{args.model}) "
        f"on {len(held_out)} CVEs"
    )
    print("(parent-technique level, matching the trainer's granularity)")
    for name, value in metrics.items():
        print(f"  {name}: {value:.4f}")
    if failures:
        print(f"  labeling failures (counted as empty): {failures}")
    print(f"{'=' * 60}\n")
    print(
        "Guidance: only trust `expand` output if this agreement is comparable "
        "to inter-analyst agreement on ATT&CK mappings. Record the number on "
        "the expanded dataset card."
    )


def run_expand(args: argparse.Namespace, catalog: dict[str, str]) -> None:
    gold = load_dataset(args.gold_dataset)
    gold_ids = {row for split in gold.values() for row in split["id"]}
    few_shot = select_few_shot(list(gold["train"]), set(), args.few_shot)
    backend = make_backend(args, build_system_text(catalog, few_shot))

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
    logger.info(f"Expanding: labeling {len(target_ids)} CVEs with {args.backend}/{args.model}")

    descriptions = _load_descriptions(args.description_dataset, set(target_ids))
    rows = []
    for i, cve_id in enumerate(target_ids, start=1):
        if cve_id not in descriptions:
            continue
        title, description = descriptions[cve_id]
        result = label_cve(backend, title, description, catalog)
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
                "llm_model": f"{args.backend}/{args.model}",
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
            commit_message=(
                f"[DATASET] LLM-labeled CVE->ATT&CK "
                f"({len(rows)} CVEs, {args.backend}/{args.model})"
            ),
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
        "--backend",
        choices=["anthropic", "ollama"],
        default="anthropic",
        help="'anthropic' uses Claude via the Anthropic API (needs "
        "ANTHROPIC_API_KEY); 'ollama' uses a local model served by Ollama "
        "(no API key).",
    )
    parser.add_argument(
        "--model",
        default="",
        help="Model to label with. Defaults per backend: "
        f"{DEFAULT_MODELS['anthropic']} (anthropic), "
        f"{DEFAULT_MODELS['ollama']} (ollama — e.g. qwen3:32b).",
    )
    parser.add_argument(
        "--ollama-url",
        default="http://localhost:11434",
        help="Base URL of the Ollama instance (ollama backend).",
    )
    parser.add_argument(
        "--ollama-timeout",
        type=int,
        default=600,
        help="Per-request timeout in seconds (ollama backend).",
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

    if not args.model:
        args.model = DEFAULT_MODELS[args.backend]

    catalog = load_technique_catalog(Path(args.cache_dir).expanduser())

    if args.mode == "validate":
        run_validate(args, catalog)
    else:
        run_expand(args, catalog)


if __name__ == "__main__":
    main()
