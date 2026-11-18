import csv
import json
import re
import uuid
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import TYPE_CHECKING, Any

import cvss
from markdown_it import MarkdownIt
from nltk.tokenize import sent_tokenize

if TYPE_CHECKING:
    from transformers import PreTrainedTokenizerBase

# CVSS v4.0 has a single score field, and producers fill it differently: some
# give the base score (CVSS-B), others the score of the full vector including
# the threat metric Exploit Maturity (CVSS-BT, e.g. NVD). cvss.CVSS4().base_score
# scores the full vector. To give every source the same reading, all v4.0
# scores are computed from the vector by cvss4_score():
# True: base metrics only (CVSS-B); False: the full vector as published.
CVSS4_BASE_ONLY = True
CVSS4_BASE_METRICS = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")


def sentences(text, num_sentences=5) -> str:
    sentences = sent_tokenize(text)[:num_sentences]
    return " ".join(sentences)


def strip_markdown(text) -> str:
    md = MarkdownIt()
    parsed = md.parse(text)
    return "".join(token.content for token in parsed if token.type == "inline")


def format_cvss_version(version: str) -> str:
    return f"cvss_v{version.replace('.', '_')}".lower()


def cvss4_base_vector(vector: str) -> str:
    """Reduce a CVSS v4.0 vector to its base metrics (CVSS-B)."""
    prefix, _, metrics = vector.strip().partition("/")
    base = [
        metric
        for metric in metrics.split("/")
        if metric.split(":", 1)[0] in CVSS4_BASE_METRICS
    ]
    return "/".join([prefix, *base])


def cvss4_score(vector: str) -> float:
    """Score a CVSS v4.0 vector with the reading set by CVSS4_BASE_ONLY."""
    if CVSS4_BASE_ONLY:
        vector = cvss4_base_vector(vector)
    return float(cvss.CVSS4(vector).base_score)


def cvss_metric_score(metric: dict[str, Any]) -> Any:
    """Score of a CVSS block of a CVE or NVD record.

    v4.0 blocks are scored from their vector with cvss4_score(), like the
    advisories, instead of taking the ``baseScore`` field as published.
    """
    if str(metric.get("version")) == "4.0" and metric.get("vectorString"):
        try:
            return cvss4_score(metric["vectorString"])
        except Exception:
            pass
    return metric["baseScore"]


def cvss_base_score(vector: str, version: str) -> str:
    """Returns the base code from a CVSS vector."""
    if version.lower() in ["cvss_v2_0", "cvss_v2"]:
        c = cvss.CVSS2(vector)
        return ", ".join([str(score) for score in c.scores()[:1]])
    elif version.lower() in ["cvss_v4_0", "cvss_v4"]:
        return str(cvss4_score(vector))
    elif version.lower() in ["cvss_v3", "cvss_v3_0", "cvss_v3_1"]:
        c = cvss.CVSS3(vector)
        return ", ".join(
            [str(score) for score in c.scores()[:1]]
        )  # slice the list to ignore temporal and environmental scores
    return vector


def extract_cpe(data) -> list[str]:
    # vulnrichement
    vuln_cpes = []
    if vulnrichment := data.get("vulnerability-lookup:meta", {}).get(
        "vulnrichment", False
    ):
        containers = json.loads(vulnrichment["containers"])

        # Check ADP section
        if "adp" in containers:
            for entry in containers["adp"]:
                if "affected" in entry:
                    for affected in entry["affected"]:
                        if "cpes" in affected:
                            vuln_cpes.extend(affected["cpes"])

        # Check CNA section
        if "cna" in containers and "affected" in containers["cna"]:
            for affected in containers["cna"]["affected"]:
                if "cpes" in affected:
                    vuln_cpes.extend(affected["cpes"])

    # fkie
    if fkie := data.get("vulnerability-lookup:meta", {}).get("fkie_nvd", False):
        if "configurations" in fkie:
            configurations = json.loads(fkie["configurations"])
            for config in configurations:
                if "nodes" in config:
                    for node in config["nodes"]:
                        if "cpeMatch" in node:
                            vuln_cpes.extend(
                                match["criteria"]
                                for match in node["cpeMatch"]
                                if "criteria" in match
                            )

    # default container
    for elem in data.get("containers", {}).get("cna", {}).get("affected", []):
        if "cpes" in elem:
            vuln_cpes.extend(elem["cpes"])

    vuln_cpes = list(dict.fromkeys(cpe.lower() for cpe in vuln_cpes))
    return vuln_cpes


def extract_cvss_cve(data) -> dict[str, float]:
    """
    Extract CVSS scores from a CVE entry, checking multiple sources.

    Args:
        data (dict): The CVE vulnerability data.

    Returns:
        dict[str, float]: A dictionary mapping CVSS version strings to base scores.
    """
    cvss_scores = {}

    # Check in the main CNA metrics section
    for metric in data.get("containers", {}).get("cna", {}).get("metrics", []):
        for key in metric:
            if key.startswith("cvssV") and "baseScore" in metric[key]:
                cvss_scores[format_cvss_version(metric[key]["version"])] = (
                    cvss_metric_score(metric[key])
                )

    # If no CVSS found, check vulnerability-lookup:meta (for embedded NVD JSON)
    if not cvss_scores:
        nvd_meta = data.get("vulnerability-lookup:meta", {}).get("nvd")
        if isinstance(nvd_meta, str):  # Ensure it's a JSON string
            try:
                nvd_data = json.loads(nvd_meta)
                for version, metrics in (
                    nvd_data.get("cve", {}).get("metrics", {}).items()
                ):
                    for key in metrics:
                        if "cvssData" in key and "baseScore" in key["cvssData"]:
                            cvss_scores[
                                format_cvss_version(key["cvssData"]["version"])
                            ] = cvss_metric_score(key["cvssData"])
            except json.JSONDecodeError:
                pass  # Ignore invalid JSON

    return cvss_scores


def extract_cvss_from_github_advisory(data) -> dict[str, float]:
    cvss_scores = {}

    # Extract CVSS scores from the 'severity' section
    for severity in data.get("severity", []):
        match = re.search(r"CVSS:(\d\.\d)", severity.get("score", ""))
        if match:
            try:
                cvss_scores[format_cvss_version(match.group(1))] = float(
                    cvss_base_score(
                        severity["score"], format_cvss_version(match.group(1))
                    )
                )
            except Exception:
                continue

    return cvss_scores


def extract_cvss_from_pysec(data) -> dict[str, float]:
    cvss_scores = {}

    for severity in data.get("severity", []):
        match = re.search(r"CVSS:(\d\.\d)", severity.get("score", ""))
        if match:
            try:
                cvss_scores[format_cvss_version(match.group(1))] = float(
                    cvss_base_score(
                        severity["score"], format_cvss_version(match.group(1))
                    )
                )
            except Exception:
                continue

    return cvss_scores


def extract_cvss_from_csaf(data) -> dict[str, float]:
    cvss_scores = {}

    for vulnerability in data.get("vulnerabilities", []):

        for score in vulnerability.get("scores", []):
            for _, value in score.items():
                if type(value) is dict:
                    if vector := value.get("vectorString", ""):
                        match = re.search(r"CVSS:(\d\.\d)", vector)
                        if match:
                            try:
                                cvss_scores[format_cvss_version(match.group(1))] = (
                                    float(
                                        cvss_base_score(
                                            vector, format_cvss_version(match.group(1))
                                        )
                                    )
                                )
                            except Exception:
                                continue

    return cvss_scores


def extract_cpe_csaf(data):
    cpe_list = []

    def extract_cpe(branches):
        """Recursively extract CPEs from product_tree branches."""
        for branch in branches:
            product = branch.get("product", {})
            cpe = product.get("product_identification_helper", {}).get("cpe")
            if cpe:
                cpe_list.append(cpe)

            # Check if the branch contains nested branches
            if "branches" in branch:
                extract_cpe(branch["branches"])

    # Start extraction from product_tree
    product_tree = data.get("product_tree", {}).get("branches", [])
    extract_cpe(product_tree)

    # Print unique CPEs
    return sorted(set(cpe_list))


def clamp_tokenizer_max_length(
    tokenizer: "PreTrainedTokenizerBase", base_model: str
) -> None:
    """Ensure the tokenizer carries a real ``model_max_length``.

    Some base models (e.g. ``hfl/chinese-macbert-base``) ship a
    ``tokenizer_config.json`` without ``model_max_length``. Transformers then
    substitutes a very large sentinel value, so ``truncation=True`` without an
    explicit ``max_length`` truncates nothing, and the broken config is pushed
    to the Hub along with our fine-tuned models — crashing consumers on inputs
    longer than the position-embedding table.

    Clamp the tokenizer to the base model's position-embedding capacity so the
    pushed ``tokenizer_config.json`` always carries a usable limit.
    """
    from transformers import AutoConfig

    config = AutoConfig.from_pretrained(base_model)
    max_positions = getattr(config, "max_position_embeddings", None)
    if max_positions is None:
        return
    # RoBERTa-style models reserve two positions for the padding offset.
    if getattr(config, "model_type", "") in ("roberta", "xlm-roberta"):
        max_positions -= 2
    if tokenizer.model_max_length > max_positions:
        tokenizer.model_max_length = max_positions


def push_emissions_report(model_save_dir: str, repo_id: str) -> bool:
    """Upload the CodeCarbon ``emissions.csv`` report to the Hugging Face Hub.

    ``trainer.push_to_hub()`` uploads ``model_save_dir`` but ignores files it
    does not recognise, so the emissions report is pushed explicitly.

    Returns ``True`` if the report existed and was uploaded.
    """
    from pathlib import Path

    emissions_file = Path(model_save_dir) / "emissions.csv"
    if not emissions_file.exists():
        return False

    from huggingface_hub import HfApi

    HfApi().upload_file(
        path_or_fileobj=str(emissions_file),
        path_in_repo="emissions.csv",
        repo_id=repo_id,
        commit_message="Add CodeCarbon emissions report",
    )
    return True


def resolve_dataset_revision(dataset_id: str, revision: str | None = None) -> str | None:
    """Return the commit of a Hugging Face Hub dataset, to pin and record it.

    ``revision`` is a branch, a tag or a commit; the default branch is used
    when it is ``None``. Returns ``None`` when ``dataset_id`` is a local path,
    or when the Hub cannot be reached (offline run on a cached dataset): the
    commit that is read is then unknown.
    """
    if Path(dataset_id).exists():
        return None

    from huggingface_hub import HfApi

    try:
        return HfApi().dataset_info(dataset_id, revision=revision).sha
    except OSError:
        return None


def read_emissions_report(model_save_dir: str) -> dict[str, str] | None:
    """Return the last run of the CodeCarbon ``emissions.csv`` report, if any."""
    emissions_file = Path(model_save_dir) / "emissions.csv"
    if not emissions_file.exists():
        return None
    with emissions_file.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    return rows[-1] if rows else None


def write_ml_bom(
    model_save_dir: str,
    *,
    repo_id: str | None,
    base_model: str,
    dataset_id: str,
    dataset_revision: str | None,
    task: str,
    license_id: str,
    metrics: list[dict[str, str]],
    properties: dict[str, Any],
) -> Path:
    """Write a CycloneDX 1.7 ML-BOM describing a training run to ``bom.cdx.json``.

    The file records what the run used and measured: the base model, the
    dataset and its commit, the evaluation metrics, the training options and
    the energy reported by CodeCarbon. ``metrics`` are CycloneDX performance
    metrics (``type``, ``value`` and an optional ``slice``); ``properties``
    maps a property name to its value.

    The file is written in the model directory, which ``trainer.push_to_hub()``
    uploads when the run pushes. The commit of the model on the Hub is only
    known after a push, so the model is identified by its name alone.
    """
    hub_url = "https://huggingface.co"

    model: dict[str, Any] = {
        "type": "machine-learning-model",
        "name": repo_id or Path(model_save_dir).resolve().name,
        "licenses": [{"license": {"id": license_id}}],
        "pedigree": {
            "ancestors": [
                {
                    "type": "machine-learning-model",
                    "name": base_model,
                    "purl": f"pkg:huggingface/{base_model}",
                    "externalReferences": [
                        {"type": "model-card", "url": f"{hub_url}/{base_model}"}
                    ],
                }
            ]
        },
    }
    if repo_id:
        model["bom-ref"] = model["purl"] = f"pkg:huggingface/{repo_id}"
        model["externalReferences"] = [
            {"type": "model-card", "url": f"{hub_url}/{repo_id}"}
        ]

    components: list[dict[str, Any]] = []
    if dataset_revision:
        dataset_ref = f"pkg:huggingface/{dataset_id}@{dataset_revision}"
        components.append(
            {
                "type": "data",
                "name": dataset_id,
                "version": dataset_revision,
                "bom-ref": dataset_ref,
                "purl": dataset_ref,
                "externalReferences": [
                    {
                        "type": "distribution",
                        "url": f"{hub_url}/datasets/{dataset_id}/tree/{dataset_revision}",
                    }
                ],
            }
        )
        datasets: list[dict[str, Any]] = [{"ref": dataset_ref}]
    else:
        # Local path, or commit unknown: describe the dataset in-line.
        datasets = [{"type": "dataset", "name": dataset_id}]

    model_card: dict[str, Any] = {
        "modelParameters": {
            "approach": {"type": "supervised"},
            "task": task,
            "datasets": datasets,
        },
        "quantitativeAnalysis": {"performanceMetrics": metrics},
        "properties": [
            {"name": name, "value": str(value)} for name, value in properties.items()
        ],
    }

    emissions = read_emissions_report(model_save_dir)
    if emissions is not None:
        energy = {"value": float(emissions["energy_consumed"]), "unit": "kWh"}
        # The schema requires an energy provider. CodeCarbon only knows where
        # the run took place, so the source of the energy is left unknown.
        location = {
            key: emissions[column]
            for key, column in (("country", "country_name"), ("region", "region"))
            if emissions.get(column)
        }
        model_card["considerations"] = {
            "environmentalConsiderations": {
                "energyConsumptions": [
                    {
                        "activity": "fine-tuning",
                        "energyProviders": [
                            {
                                "description": "Electricity at the location of the training run, as reported by CodeCarbon.",
                                "organization": {"address": location} if location else {},
                                "energySource": "unknown",
                                "energyProvided": energy,
                            }
                        ],
                        "activityEnergyCost": energy,
                        # CodeCarbon reports kilograms of CO2 equivalent.
                        "co2CostEquivalent": {
                            "value": float(emissions["emissions"]) / 1000,
                            "unit": "tCO2eq",
                        },
                    }
                ]
            }
        }
    model["modelCard"] = model_card

    bom: dict[str, Any] = {
        "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "VulnTrain",
                        "version": metadata.version("VulnTrain"),
                    }
                ]
            },
            "component": model,
        },
    }
    if components:
        bom["components"] = components

    bom_file = Path(model_save_dir) / "bom.cdx.json"
    bom_file.write_text(json.dumps(bom, indent=2) + "\n")
    return bom_file
