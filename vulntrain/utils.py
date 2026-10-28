import json
import re
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
