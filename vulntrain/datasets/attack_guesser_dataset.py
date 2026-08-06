"""Build a CVE → MITRE ATT&CK techniques mapping dataset (Phase 1).

Combines the two hand-curated MITRE CTID mapping projects into a single
Hugging Face dataset with vulnerability descriptions, suitable for training
a multi-label ATT&CK technique classifier:

- attack_to_cve (2021): ~840 CVEs mapped following the "Mapping ATT&CK to
  CVE for Impact" methodology (exploitation technique / primary impact /
  secondary impact).
- Mappings Explorer KEV mappings: ~420 CISA KEV CVEs mapped with the same
  methodology against a recent ATT&CK release.

Technique IDs from both sources are normalized against the current
enterprise ATT&CK STIX data (revoked techniques are remapped to their
successor, deprecated ones are dropped).

Descriptions are joined from the CIRCL/vulnerability-scores dataset, with a
fallback on the Vulnerability-Lookup API for CVEs missing there.

Structured metadata columns (dataset v2, additive): the raw CVE record is
fetched from the Vulnerability-Lookup API (cached on disk) for every CVE,
and the CVSS vector string (highest available version, CNA container
preferred over ADP), the CWE assignments, and the affected vendor/product
pairs are extracted from the CNA and ADP (e.g. CISA Vulnrichment)
containers. CPE lists are joined from CIRCL/vulnerability-scores with a
fallback on the raw record.

The automatically derived CVE→CWE→CAPEC→ATT&CK chain from the CVE2CAPEC
project (https://github.com/Galeax/CVE2CAPEC) is included as a separate
`techniques_derived` column. These labels are far too noisy to train on
(see docs/attack-techniques-dataset.md) but are useful as a candidate
prior or evaluation baseline.
"""

import argparse
import csv
import gzip
import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from datasets import Dataset, DatasetDict, load_dataset

from vulntrain.config import VULNERABILITY_LOOKUP_TOKEN

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

ATTACK_TO_CVE_CSV_URL = "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack_to_cve/master/Att%26ckToCveMappings.csv"
KEV_MAPPINGS_URL = "https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/kev/attack-16.1/kev-07.28.2025/enterprise/kev-07.28.2025_attack-16.1-enterprise.json"
ENTERPRISE_ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
CVE2CAPEC_DATABASE_URL = (
    "https://raw.githubusercontent.com/Galeax/CVE2CAPEC/main/database/CVE-{year}.jsonl.gz"
)
DEFAULT_VULN_LOOKUP_URL = "https://vulnerability.circl.lu"

MAPPING_TYPE_COLUMNS = {
    "exploitation_technique": "exploitation_techniques",
    "primary_impact": "primary_impact",
    "secondary_impact": "secondary_impact",
}
TECHNIQUE_BUCKETS = list(MAPPING_TYPE_COLUMNS.values()) + ["uncategorized"]


def download_file(url: str, cache_dir: Path, filename: str) -> Path:
    """Download url into cache_dir/filename unless already present."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    destination = cache_dir / filename
    if destination.exists():
        logger.info(f"Using cached {destination}")
        return destination
    logger.info(f"Downloading {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "VulnTrain"})
    with urllib.request.urlopen(request) as response:
        destination.write_bytes(response.read())
    return destination


class AttackNormalizer:
    """Normalize technique IDs against the current enterprise ATT&CK release.

    Revoked techniques are remapped to their successor (via the STIX
    ``revoked-by`` relationships); deprecated techniques have no successor
    and normalize to None.
    """

    def __init__(self, stix_bundle: dict[str, Any]):
        self.version = "unknown"
        self.valid_ids: set[str] = set()
        self.remap: dict[str, str] = {}
        self.remapped_count: Counter[str] = Counter()
        self.dropped_count: Counter[str] = Counter()

        stix_to_external: dict[str, str] = {}
        for obj in stix_bundle.get("objects", []):
            obj_type = obj.get("type")
            if obj_type == "x-mitre-collection":
                self.version = obj.get("x_mitre_version", "unknown")
            if obj_type != "attack-pattern":
                continue
            external_id = next(
                (
                    reference.get("external_id")
                    for reference in obj.get("external_references", [])
                    if reference.get("source_name") == "mitre-attack"
                ),
                None,
            )
            if not external_id:
                continue
            stix_to_external[obj["id"]] = external_id
            if not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
                self.valid_ids.add(external_id)

        for obj in stix_bundle.get("objects", []):
            if (
                obj.get("type") == "relationship"
                and obj.get("relationship_type") == "revoked-by"
            ):
                source = stix_to_external.get(obj.get("source_ref", ""))
                target = stix_to_external.get(obj.get("target_ref", ""))
                if source and target and source != target:
                    self.remap[source] = target

    def normalize(self, technique_id: str) -> Optional[str]:
        original = technique_id
        seen: set[str] = set()
        while technique_id in self.remap and technique_id not in seen:
            seen.add(technique_id)
            technique_id = self.remap[technique_id]
        if technique_id in self.valid_ids:
            if technique_id != original:
                self.remapped_count[f"{original}->{technique_id}"] += 1
            return technique_id
        self.dropped_count[original] += 1
        return None


def new_mapping_entry() -> dict[str, Any]:
    entry: dict[str, Any] = {bucket: set() for bucket in TECHNIQUE_BUCKETS}
    entry["label_sources"] = set()
    return entry


def parse_attack_to_cve_csv(
    path: Path, mappings: dict[str, dict[str, Any]]
) -> None:
    """Parse the 2021 CTID attack_to_cve CSV into per-CVE technique sets."""
    csv_columns = {
        "Exploitation Technique": "exploitation_techniques",
        "Primary Impact": "primary_impact",
        "Secondary Impact": "secondary_impact",
        "Uncategorized": "uncategorized",
    }
    with open(path, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            cve_id = (row.get("CVE ID") or "").strip()
            if not cve_id.startswith("CVE-"):
                continue
            entry = mappings.setdefault(cve_id, new_mapping_entry())
            entry["label_sources"].add("ctid_cve")
            for column, bucket in csv_columns.items():
                entry[bucket].update(TECHNIQUE_RE.findall(row.get(column) or ""))


def parse_kev_mappings(path: Path, mappings: dict[str, dict[str, Any]]) -> None:
    """Parse the CTID Mappings Explorer KEV mappings JSON."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    for obj in data.get("mapping_objects", []):
        cve_id = (obj.get("capability_id") or "").strip()
        technique_id = (obj.get("attack_object_id") or "").strip()
        if not cve_id.startswith("CVE-") or not TECHNIQUE_RE.fullmatch(technique_id):
            continue
        bucket = MAPPING_TYPE_COLUMNS.get(
            obj.get("mapping_type", ""), "uncategorized"
        )
        entry = mappings.setdefault(cve_id, new_mapping_entry())
        entry["label_sources"].add("ctid_kev")
        entry[bucket].add(technique_id)


def load_cve2capec_techniques(
    cache_dir: Path, cve_ids: set[str]
) -> dict[str, list[str]]:
    """Collect the derived (weak) techniques from CVE2CAPEC for the given CVEs.

    Only the per-year database files matching years present in cve_ids are
    downloaded.
    """
    derived: dict[str, list[str]] = {}
    years = sorted({cve_id.split("-")[1] for cve_id in cve_ids})
    for year in years:
        url = CVE2CAPEC_DATABASE_URL.format(year=year)
        try:
            path = download_file(url, cache_dir, f"cve2capec-{year}.jsonl.gz")
        except urllib.error.URLError as e:
            logger.warning(f"Could not fetch CVE2CAPEC database for {year}: {e}")
            continue
        with gzip.open(path, "rt", encoding="utf-8") as f:
            for line in f:
                record = json.loads(line)
                for cve_id, data in record.items():
                    if cve_id in cve_ids:
                        derived[cve_id] = sorted(
                            f"T{technique}"
                            for technique in data.get("TECHNIQUES", [])
                        )
    return derived


def load_descriptions(
    dataset_id: str, cve_ids: set[str]
) -> dict[str, tuple[str, str, list[str]]]:
    """Join (title, description, cpes) from the given Hugging Face dataset."""
    logger.info(f"Loading descriptions from {dataset_id}")
    dataset = load_dataset(dataset_id)
    found: dict[str, tuple[str, str, list[str]]] = {}
    for split in dataset.values():
        indices = [
            i
            for i, vuln_id in enumerate(split["id"])
            if vuln_id in cve_ids and vuln_id not in found
        ]
        for row in split.select(indices):
            found[row["id"]] = (
                row.get("title") or "",
                row.get("description") or "",
                row.get("cpes") or [],
            )
    return found


def fetch_raw_record(
    vuln_id: str, cache_dir: Path, api_url: str, token: str = ""
) -> Optional[dict[str, Any]]:
    """Fetch a raw CVE record from the Vulnerability-Lookup API, cached on
    disk so re-runs never hit the network. Sends the API token as X-API-KEY
    when configured (higher rate limits); honors Retry-After on HTTP 429."""
    cache_path = cache_dir / "vuln-records" / f"{vuln_id}.json"
    if cache_path.exists():
        cached: dict[str, Any] = json.loads(cache_path.read_text(encoding="utf-8"))
        return cached

    headers = {"User-Agent": "VulnTrain"}
    if token:
        headers["X-API-KEY"] = token
    url = f"{api_url.rstrip('/')}/api/vulnerability/{vuln_id}"
    local = urllib.parse.urlparse(url).hostname in {"127.0.0.1", "localhost", "::1"}
    request = urllib.request.Request(url, headers=headers)
    for attempt in range(5):
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                record: dict[str, Any] = json.load(response)
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 4:
                delay = min(float(e.headers.get("Retry-After") or 60), 120.0)
                logger.info(
                    f"Rate limited by Vulnerability-Lookup on {vuln_id}, "
                    f"waiting {delay:.0f}s (configure an API token in "
                    f"conf.py or VULNERABILITY_LOOKUP_TOKEN to avoid this)"
                )
                time.sleep(delay)
                continue
            logger.warning(f"Vulnerability-Lookup failed for {vuln_id}: {e}")
            return None
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
            logger.warning(f"Vulnerability-Lookup failed for {vuln_id}: {e}")
            return None
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(record), encoding="utf-8")
        if not local:
            time.sleep(1.0)  # stay polite; only on actual network fetches
        return record
    return None


def iter_containers(record: dict[str, Any]) -> list[dict[str, Any]]:
    """CNA container first, then ADP containers (CISA Vulnrichment etc.)."""
    containers = record.get("containers", {})
    result = []
    if cna := containers.get("cna"):
        result.append(cna)
    result.extend(containers.get("adp") or [])
    return result


CVSS_VERSION_PRIORITY = ["4.0", "3.1", "3.0", "2.0"]


def extract_cvss_vector(record: dict[str, Any]) -> tuple[str, str]:
    """Return (vector string, version) — the highest CVSS version found,
    with the CNA container taking precedence over ADP within a version."""
    best = ("", "")
    best_rank = len(CVSS_VERSION_PRIORITY)
    for container in iter_containers(record):
        for metric in container.get("metrics") or []:
            for key, value in metric.items():
                if not key.startswith("cvssV") or not isinstance(value, dict):
                    continue
                vector = value.get("vectorString") or ""
                version = value.get("version") or ""
                if not vector or version not in CVSS_VERSION_PRIORITY:
                    continue
                rank = CVSS_VERSION_PRIORITY.index(version)
                if rank < best_rank:
                    best, best_rank = (vector, version), rank
    return best


def extract_cwes(record: dict[str, Any]) -> list[str]:
    """CWE assignments from the CNA and ADP problemTypes, as display strings
    ('CWE-79 Cross-site Scripting'); plain-text weakness descriptions without
    a CWE id are kept as-is. Deduplicated by CWE id (or lowercased text)."""
    found: dict[str, str] = {}
    for container in iter_containers(record):
        for problem in container.get("problemTypes") or []:
            for description in problem.get("descriptions") or []:
                text = (description.get("description") or "").strip()
                cwe_id = (description.get("cweId") or "").strip()
                if text.lower() in {"n/a", "noinfo", "other", "not applicable"}:
                    text = ""
                if cwe_id and text and not text.startswith(cwe_id):
                    display = f"{cwe_id} {text}"
                else:
                    display = text or cwe_id
                if not display:
                    continue
                found.setdefault(cwe_id or display.lower(), display)
    # Drop plain-text entries duplicated by an id-bearing one (e.g. a CNA
    # 'Deserialization of Untrusted Data' next to the ADP 'CWE-502 ...').
    id_texts = " || ".join(
        display.lower() for key, display in found.items() if key.startswith("CWE-")
    )
    return [
        display
        for key, display in found.items()
        if key.startswith("CWE-") or display.lower() not in id_texts
    ]


def extract_affected_products(record: dict[str, Any]) -> list[str]:
    """'vendor product' pairs from the affected sections ('n/a' filtered)."""
    pairs: dict[str, None] = {}
    for container in iter_containers(record):
        for affected in container.get("affected") or []:
            vendor = (affected.get("vendor") or "").strip()
            product = (affected.get("product") or "").strip()
            if vendor.lower() == "n/a":
                vendor = ""
            if not product or product.lower() == "n/a":
                continue
            pairs.setdefault(f"{vendor} {product}".strip(), None)
    return list(pairs)


def extract_record_cpes(record: dict[str, Any]) -> list[str]:
    """CPE fallback from the raw record's affected sections."""
    cpes: dict[str, None] = {}
    for container in iter_containers(record):
        for affected in container.get("affected") or []:
            for cpe in affected.get("cpes") or []:
                cpes.setdefault(cpe.lower(), None)
    return list(cpes)


def extract_description(record: dict[str, Any]) -> Optional[tuple[str, str]]:
    """Fallback (title, description) from a raw record's CNA container."""
    cna = record.get("containers", {}).get("cna", {})
    title = cna.get("title", "")
    description = next(
        (
            d.get("value", "")
            for d in cna.get("descriptions", [])
            if d.get("lang", "").startswith("en")
        ),
        "",
    )
    if not description:
        return None
    return title, description


def build_dataset(args: argparse.Namespace) -> DatasetDict:
    cache_dir = Path(args.cache_dir).expanduser()

    stix_path = download_file(
        ENTERPRISE_ATTACK_STIX_URL, cache_dir, "enterprise-attack.json"
    )
    with open(stix_path, encoding="utf-8") as f:
        normalizer = AttackNormalizer(json.load(f))
    logger.info(
        f"Normalizing against enterprise ATT&CK v{normalizer.version} "
        f"({len(normalizer.valid_ids)} active techniques)"
    )

    mappings: dict[str, dict[str, Any]] = {}
    csv_path = download_file(
        args.cve_mappings_url, cache_dir, "ctid-attack-to-cve.csv"
    )
    parse_attack_to_cve_csv(csv_path, mappings)
    kev_path = download_file(args.kev_mappings_url, cache_dir, "ctid-kev-mappings.json")
    parse_kev_mappings(kev_path, mappings)
    logger.info(f"Collected gold mappings for {len(mappings)} CVEs")

    # Normalize technique IDs to the current ATT&CK release.
    for entry in mappings.values():
        for bucket in TECHNIQUE_BUCKETS:
            entry[bucket] = {
                normalized
                for technique_id in entry[bucket]
                if (normalized := normalizer.normalize(technique_id))
            }
    if normalizer.remapped_count:
        logger.info(
            f"Remapped revoked techniques: {dict(normalizer.remapped_count)}"
        )
    if normalizer.dropped_count:
        logger.warning(
            f"Dropped techniques absent from ATT&CK v{normalizer.version}: "
            f"{dict(normalizer.dropped_count)}"
        )

    cve_ids = set(mappings)
    derived = {} if args.skip_cve2capec else load_cve2capec_techniques(cache_dir, cve_ids)
    descriptions = load_descriptions(args.description_dataset, cve_ids)

    logger.info(
        f"Fetching raw records for {len(cve_ids)} CVEs from the "
        "Vulnerability-Lookup API (disk-cached; only uncached CVEs hit the "
        "network)"
    )
    token = os.environ.get("VULNERABILITY_LOOKUP_TOKEN", "") or VULNERABILITY_LOOKUP_TOKEN
    records: dict[str, dict[str, Any]] = {}
    for index, vuln_id in enumerate(sorted(cve_ids), start=1):
        record = fetch_raw_record(vuln_id, cache_dir, args.vuln_lookup_url, token)
        if record:
            records[vuln_id] = record
        if index % 200 == 0:
            logger.info(f"  {index}/{len(cve_ids)} records fetched")
    logger.info(f"Raw records available for {len(records)}/{len(cve_ids)} CVEs")

    missing = sorted(cve_ids - set(descriptions))
    if missing:
        logger.info(
            f"{len(missing)} CVEs missing from {args.description_dataset}, "
            "falling back on the raw records"
        )
        for vuln_id in missing:
            if vuln_id in records:
                result = extract_description(records[vuln_id])
                if result:
                    descriptions[vuln_id] = (result[0], result[1], [])

    rows = []
    skipped_no_description = 0
    skipped_no_technique = 0
    for cve_id in sorted(mappings):
        entry = mappings[cve_id]
        techniques = sorted(
            set().union(*(entry[bucket] for bucket in TECHNIQUE_BUCKETS))
        )
        if not techniques:
            skipped_no_technique += 1
            continue
        if cve_id not in descriptions:
            skipped_no_description += 1
            continue
        title, description, cpes = descriptions[cve_id]
        record = records.get(cve_id, {})
        cvss_vector, cvss_version = extract_cvss_vector(record)
        rows.append(
            {
                "id": cve_id,
                "title": title,
                "description": description,
                "exploitation_techniques": sorted(entry["exploitation_techniques"]),
                "primary_impact": sorted(entry["primary_impact"]),
                "secondary_impact": sorted(entry["secondary_impact"]),
                "techniques": techniques,
                "techniques_derived": derived.get(cve_id, []),
                "label_sources": sorted(entry["label_sources"]),
                "attack_version": normalizer.version,
                "cvss_vector": cvss_vector,
                "cvss_version": cvss_version,
                "cwes": extract_cwes(record),
                "affected_products": extract_affected_products(record),
                "cpes": cpes or extract_record_cpes(record),
            }
        )
    if skipped_no_technique:
        logger.warning(
            f"Skipped {skipped_no_technique} CVEs with no technique left "
            "after normalization"
        )
    if skipped_no_description:
        logger.warning(
            f"Skipped {skipped_no_description} CVEs with no description found"
        )

    print_statistics(rows)

    dataset = Dataset.from_list(rows)
    split = dataset.train_test_split(test_size=0.1, seed=42)
    return DatasetDict({"train": split["train"], "test": split["test"]})


def print_statistics(rows: list[dict[str, Any]]) -> None:
    source_counts: Counter[str] = Counter(
        "+".join(row["label_sources"]) for row in rows
    )
    technique_counts: Counter[str] = Counter(
        technique for row in rows for technique in row["techniques"]
    )
    labels_per_cve: Counter[int] = Counter(len(row["techniques"]) for row in rows)

    print(f"\n{'=' * 60}")
    print(f"Dataset rows: {len(rows)}")
    print(f"Rows per label source: {dict(source_counts)}")
    print(f"Distinct techniques: {len(technique_counts)}")
    print("Techniques per CVE distribution:")
    for count in sorted(labels_per_cve):
        print(f"  {count}: {labels_per_cve[count]}")
    print("Top 20 techniques:")
    for technique, count in technique_counts.most_common(20):
        print(f"  {technique}: {count}")
    supported = sum(1 for c in technique_counts.values() if c >= 5)
    print(f"Techniques with >= 5 examples: {supported}")

    metadata_fields = ["cvss_vector", "cwes", "affected_products", "cpes"]
    print("Metadata coverage (overall / per label source):")
    groups: dict[str, list[dict[str, Any]]] = {"all": rows}
    for row in rows:
        groups.setdefault("+".join(row["label_sources"]), []).append(row)
    for name, group in groups.items():
        coverage = " ".join(
            f"{field}={sum(1 for r in group if r[field]) / len(group):.1%}"
            for field in metadata_fields
        )
        print(f"  {name} (n={len(group)}): {coverage}")
    cvss_versions = Counter(row["cvss_version"] for row in rows if row["cvss_version"])
    print(f"CVSS versions: {dict(cvss_versions)}")
    print(f"{'=' * 60}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build the CVE -> MITRE ATT&CK techniques mapping dataset "
        "from the MITRE CTID gold mappings."
    )
    parser.add_argument(
        "--repo-id",
        default="CIRCL/vulnerability-attack-techniques",
        help="Hugging Face Hub repo ID to push the dataset to.",
    )
    parser.add_argument(
        "--push",
        action="store_true",
        help="Push the dataset to the Hugging Face Hub.",
    )
    parser.add_argument(
        "--output-dir",
        default="",
        help="Optional local directory to save the dataset to (save_to_disk).",
    )
    parser.add_argument(
        "--description-dataset",
        default="CIRCL/vulnerability-scores",
        help="Hugging Face dataset used to join titles and descriptions.",
    )
    parser.add_argument(
        "--cache-dir",
        default="~/.cache/vulntrain",
        help="Directory where downloaded source files are cached.",
    )
    parser.add_argument(
        "--vuln-lookup-url",
        dest="vuln_lookup_url",
        default=DEFAULT_VULN_LOOKUP_URL,
        help="Base URL of the Vulnerability-Lookup instance used for raw CVE "
        "records (e.g. http://127.0.0.1:5000 for a local instance). An API "
        "token can be set in conf.py (VULNERABILITY_LOOKUP_TOKEN) or via the "
        "environment variable of the same name.",
    )
    parser.add_argument(
        "--cve-mappings-url",
        default=ATTACK_TO_CVE_CSV_URL,
        help="URL of the CTID attack_to_cve CSV.",
    )
    parser.add_argument(
        "--kev-mappings-url",
        default=KEV_MAPPINGS_URL,
        help="URL of the CTID Mappings Explorer KEV->ATT&CK JSON. Update when "
        "CTID publishes mappings for a newer ATT&CK release.",
    )
    parser.add_argument(
        "--skip-cve2capec",
        action="store_true",
        help="Do not include the derived (weak) CVE2CAPEC techniques column.",
    )
    args = parser.parse_args()

    dataset_dict = build_dataset(args)
    print(dataset_dict)

    if args.output_dir:
        dataset_dict.save_to_disk(args.output_dir)
        logger.info(f"Dataset saved to {args.output_dir}")
    if args.push:
        dataset_dict.push_to_hub(
            args.repo_id,
            commit_message=f"[DATASET] CVE to ATT&CK techniques mapping "
            f"({len(dataset_dict['train']) + len(dataset_dict['test'])} CVEs)",
            private=False,
        )
        logger.info(f"Dataset pushed to {args.repo_id}")


if __name__ == "__main__":
    main()
