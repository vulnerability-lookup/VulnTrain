"""Official enterprise ATT&CK technique texts from the MITRE STIX bundle.

Shared by the label-semantics (bi-encoder) trainer and the ATT&CK
validators, so training-time and evaluation-time technique texts are built
identically. STIX descriptions carry wiki-style markup --- inline
citations ``(Citation: ...)``, markdown links, ``<code>`` tags --- that is
noise for a sentence encoder, so the texts are stripped before use.
"""

import json
import logging
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_CITATION_RE = re.compile(r"\(Citation: [^)]*\)")
_MARKDOWN_LINK_RE = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_HTML_TAG_RE = re.compile(r"</?[a-zA-Z][^>]*>")


def strip_stix_markup(text: str) -> str:
    """Remove citations, markdown links (keeping the link text) and HTML
    tags; collapse whitespace."""
    text = _CITATION_RE.sub("", text)
    text = _MARKDOWN_LINK_RE.sub(r"\1", text)
    text = _HTML_TAG_RE.sub("", text)
    return " ".join(text.split())


def load_technique_texts(
    stix_path: Path,
    vocabulary: Optional[list[str]] = None,
    parents_only: bool = False,
) -> dict[str, str]:
    """Return ``'Name. Description'`` (markup stripped) per technique ID.

    All active (non-revoked, non-deprecated) techniques in the bundle by
    default; restricted to ``vocabulary`` if given (with a warning for
    vocabulary entries the bundle has no text for), and to parent
    techniques if ``parents_only``.
    """
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
        if not external_id:
            continue
        if parents_only and "." in external_id:
            continue
        if vocabulary is not None and external_id not in vocabulary:
            continue
        name = obj.get("name", "")
        description = strip_stix_markup(obj.get("description", ""))
        texts[external_id] = f"{name}. {description}".strip()
    if vocabulary is not None:
        missing = set(vocabulary) - set(texts)
        if missing:
            logger.warning(f"No STIX text found for techniques: {sorted(missing)}")
    return texts
