"""Verbalize the structured metadata columns of the
CIRCL/vulnerability-attack-techniques dataset (v2) into model input text.

Shared by the ATT&CK trainer and validator so training and evaluation
always build identical inputs. The enabled signals are recorded in the
trained model's config (``metadata_inputs``), and the validator reads them
back from there.

Design choices (metadata-ablation experiment, E3):
- CVSS vectors are verbalized version-neutrally (v2/v3.x/v4.0 metrics map
  to the same phrases) so the version mix in the dataset does not leak
  into the text representation.
- Missing metadata renders as an explicit ``unknown`` under a constant
  section header, so absence is a signal and the text structure is
  identical across rows.
"""

from typing import Any, Iterable

METADATA_SIGNALS = ("cvss", "cwe", "products", "derived")

# (metric code, label, value -> phrase). Codes cover CVSS v2, v3.x and
# v4.0; temporal/environmental metrics are intentionally skipped.
_CVSS_METRICS: list[tuple[str, str, dict[str, str]]] = [
    (
        "AV",
        "attack vector",
        {"N": "network", "A": "adjacent network", "L": "local", "P": "physical"},
    ),
    ("AC", "attack complexity", {"L": "low", "M": "medium", "H": "high"}),
    ("AT", "attack requirements", {"N": "none", "P": "present"}),
    ("Au", "authentication", {"N": "none", "S": "single", "M": "multiple"}),
    ("PR", "privileges required", {"N": "none", "L": "low", "H": "high"}),
    (
        "UI",
        "user interaction",
        {"N": "none", "R": "required", "P": "passive", "A": "active"},
    ),
    ("S", "scope", {"U": "unchanged", "C": "changed"}),
    (
        "C",
        "confidentiality impact",
        {"N": "none", "L": "low", "P": "partial", "H": "high", "C": "complete"},
    ),
    (
        "I",
        "integrity impact",
        {"N": "none", "L": "low", "P": "partial", "H": "high", "C": "complete"},
    ),
    (
        "A",
        "availability impact",
        {"N": "none", "L": "low", "P": "partial", "H": "high", "C": "complete"},
    ),
    ("VC", "confidentiality impact", {"N": "none", "L": "low", "H": "high"}),
    ("VI", "integrity impact", {"N": "none", "L": "low", "H": "high"}),
    ("VA", "availability impact", {"N": "none", "L": "low", "H": "high"}),
    ("SC", "subsequent confidentiality impact", {"N": "none", "L": "low", "H": "high"}),
    ("SI", "subsequent integrity impact", {"N": "none", "L": "low", "H": "high"}),
    ("SA", "subsequent availability impact", {"N": "none", "L": "low", "H": "high"}),
]
_CVSS_LOOKUP = {code: (label, values) for code, label, values in _CVSS_METRICS}


def verbalize_cvss(vector: str) -> str:
    """'CVSS:3.1/AV:N/AC:L/...' -> 'CVSS: attack vector network; ...'."""
    if not vector:
        return "CVSS: unknown."
    phrases = []
    for component in vector.split("/"):
        code, _, value = component.partition(":")
        if code == "CVSS":
            continue
        if code in _CVSS_LOOKUP:
            label, values = _CVSS_LOOKUP[code]
            if value in values:
                phrases.append(f"{label} {values[value]}")
    if not phrases:
        return "CVSS: unknown."
    return "CVSS: " + "; ".join(phrases) + "."


def cpe_vendor_product(cpe: str) -> str:
    """'cpe:2.3:a:cisco:managed_services_accelerator:...' -> 'cisco managed services accelerator'."""
    fields = cpe.split(":")
    if len(fields) < 5 or fields[0] != "cpe":
        return ""
    vendor, product = fields[3], fields[4]
    return f"{vendor} {product}".replace("_", " ").strip()


def _unique(items: Iterable[str], limit: int) -> list[str]:
    """First `limit` distinct items (case-insensitive), original casing kept."""
    seen: dict[str, str] = {}
    for item in items:
        key = " ".join(item.lower().split())
        if key and key not in seen:
            seen[key] = " ".join(item.split())
        if len(seen) >= limit:
            break
    return list(seen.values())


def _collapse_repeated_vendor(product: str) -> str:
    """'Cisco Cisco Managed Services Accelerator' -> 'Cisco Managed ...'."""
    words = product.split()
    if len(words) >= 2 and words[0].lower() == words[1].lower():
        return " ".join(words[1:])
    return product


def build_input_text(example: dict[str, Any], signals: Iterable[str]) -> str:
    """Model input text: title + description, plus one line per enabled
    metadata signal. With no signals this reproduces the v1 input exactly."""
    parts = [
        f"{example.get('title') or ''}\n{example.get('description') or ''}".strip()
    ]
    enabled = set(signals)
    unknown = set(enabled) - set(METADATA_SIGNALS)
    if unknown:
        raise ValueError(f"Unknown metadata signals: {sorted(unknown)}")
    if "cvss" in enabled:
        parts.append(verbalize_cvss(example.get("cvss_vector") or ""))
    if "cwe" in enabled:
        cwes = _unique(example.get("cwes") or [], limit=5)
        parts.append("CWE: " + ("; ".join(cwes) if cwes else "unknown") + ".")
    if "products" in enabled:
        products = _unique(
            [
                _collapse_repeated_vendor(product)
                for product in example.get("affected_products") or []
            ]
            + [cpe_vendor_product(cpe) for cpe in example.get("cpes") or []],
            limit=5,
        )
        parts.append(
            "Affected products: "
            + (", ".join(products) if products else "unknown")
            + "."
        )
    if "derived" in enabled:
        derived = _unique(example.get("techniques_derived") or [], limit=15)
        parts.append(
            "CWE-chain candidate techniques: "
            + (", ".join(derived) if derived else "none")
            + "."
        )
    return "\n".join(parts)
