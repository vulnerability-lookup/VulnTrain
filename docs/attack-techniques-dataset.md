# CVE → MITRE ATT&CK techniques dataset

This page documents the methodology behind the
[CIRCL/vulnerability-attack-techniques](https://huggingface.co/datasets/CIRCL/vulnerability-attack-techniques)
dataset and the design decisions that led to it. The goal (tracked in
[VulnTrain issue #6](https://github.com/vulnerability-lookup/VulnTrain/issues/6))
is to train a model that suggests MITRE ATT&CK techniques from a
vulnerability description: CVSS tells you *how bad* a vulnerability is, CWE
tells you *what kind of flaw* it is, ATT&CK tells defenders *what adversary
behavior to expect and detect*. Very few public models cover that gap.

## Overall plan

- **Phase 1** (this page): build a curated CVE → ATT&CK mapping dataset from
  the hand-made MITRE CTID mappings, joined with descriptions from
  [CIRCL/vulnerability-scores](https://huggingface.co/datasets/CIRCL/vulnerability-scores).
- **Phase 2**: train a multi-label classifier on the curated labels
  (`vulntrain-train-attack-classification`, see below), and later expand the
  dataset with LLM-assisted labeling validated against the Phase 1 gold set.

Generate the dataset with:

```bash
vulntrain-dataset-attack-generation --output-dir ./attack-dataset       # dry run, local only
vulntrain-dataset-attack-generation --push --repo-id CIRCL/vulnerability-attack-techniques
```

Source files (CTID mappings, ATT&CK STIX data, CVE2CAPEC databases) are
cached in `~/.cache/vulntrain`.

## Candidate label sources, and what we measured

There is no large ground-truth CVE → ATT&CK dataset. The candidate sources
fall into two categories: small and hand-curated, or large and automatically
derived. We evaluated both before deciding.

### Gold sources: the MITRE CTID mappings (used as training labels)

The MITRE Center for Threat-Informed Defense (CTID) produced two mapping
efforts, both following the
["Mapping ATT&CK to CVE for Impact" methodology](https://github.com/center-for-threat-informed-defense/attack_to_cve/blob/master/methodology.md),
which assigns each CVE up to three kinds of techniques:

- **Exploitation technique** — how the vulnerability is exploited
  (e.g. T1190 *Exploit Public-Facing Application*).
- **Primary impact** — what the exploitation directly yields
  (e.g. T1059 *Command and Scripting Interpreter*).
- **Secondary impact** — what the attacker can do afterwards.

The two sources:

| Source | CVEs | ATT&CK version | Notes |
|--------|------|----------------|-------|
| [attack_to_cve](https://github.com/center-for-threat-informed-defense/attack_to_cve) (2021) | ~840 | v9 era | CSV, the original project |
| [Mappings Explorer KEV mappings](https://center-for-threat-informed-defense.github.io/mappings-explorer/) | ~420 | 16.1 | JSON, CISA Known Exploited Vulnerabilities, includes per-mapping justification comments |

Both are Apache-2.0 licensed. Together they cover 1,228 distinct CVEs
(1,207 rows after normalization and description joining) — small, but every
label was written by an analyst. The resulting technique distribution
matches what one would expect from real-world exploitation: T1190 (348),
T1059 (262), T1203 (213), T1068 (189), with 192 distinct techniques of
which 66 have at least 5 examples.

### Derived source: CVE2CAPEC (included, but not as training labels)

[CVE2CAPEC](https://github.com/Galeax/CVE2CAPEC) (Galeax, GPLv3) maintains a
daily-updated database chaining CVE → CWE → CAPEC → ATT&CK through the
official cross-framework mappings. It is an impressive piece of automation
with near-complete coverage, and it is referenced from issue #6, so we
analyzed whether its technique labels could serve as training targets.

Measurements on its `CVE-2024.jsonl` database file (39,156 CVEs):

- 88.3% of CVEs receive at least one technique — coverage is excellent.
- But the **fan-out is huge**: the median CVE gets between 4 and 20
  techniques, and 7,381 CVEs (19%) get 20 or more.
- The **most frequent technique overall is T1574.007** (*Path Interception
  by PATH Environment Variable*), tagged on **53% of all labeled CVEs** —
  followed by T1574.006, T1562.003 and T1134.001, all around 50%. These
  frequencies bear no relation to how vulnerabilities are actually
  exploited; they are artifacts of the CWE → CAPEC → ATT&CK table expansion,
  where one generic CWE fans out into dozens of CAPECs and techniques.
- Spot check: CVE-2024-21732, an XSS-family CVE (CWE-79), maps to 48 CAPECs
  and to techniques T1027 (*Obfuscated Files or Information*) and
  T1574.006/.007 (*Hijack Execution Flow*) — nothing related to XSS or
  drive-by exploitation.

**Conclusion**: training on these labels would teach the model the noise of
the mapping tables rather than adversary behavior. The derived techniques
are still valuable, so the dataset keeps them in a clearly separated
`techniques_derived` column, useful as:

1. a **candidate prior** at inference time (only suggest techniques
   compatible with the CWE chain);
2. a **baseline** that any trained model must beat;
3. a comparison column for studying where the deterministic chain diverges
   from analyst judgment.

### Other sources considered

- **BRON** (MIT Lincoln Laboratory): same CWE → CAPEC → ATT&CK chain as
  CVE2CAPEC, same noise profile.
- **TRAM** (CTID): maps *threat reports* to ATT&CK, not CVE descriptions —
  a different text distribution.
- Academic work: *CVE2ATT&CK* (Grigorescu et al., 2022) fine-tuned BERT on
  ~1,800 CVEs and 31 techniques; *SMET* (Abdeen et al., ACSAC 2023)
  deliberately avoided supervised classification because of label scarcity
  and used semantic similarity against ATT&CK technique descriptions
  instead. SMET-style similarity ranking is a baseline worth implementing
  in Phase 2.

## Pipeline

`vulntrain/datasets/attack_guesser_dataset.py` performs the following steps:

1. **Fetch** the two CTID mapping files.
2. **Normalize** every technique ID against the current enterprise ATT&CK
   STIX data ([attack-stix-data](https://github.com/mitre-attack/attack-stix-data)):
   techniques revoked since 2021 are remapped to their successor via the
   STIX `revoked-by` relationships (e.g. T1562 *Impair Defenses* → T1685
   *Disable or Modify Tools*, revoked in v19); deprecated techniques have no
   successor and are dropped with a warning. Mobile and ICS techniques
   (T1404, T0855, …) present in a handful of 2021 mappings are also dropped
   — the dataset targets the enterprise ATT&CK domain only, which costs
   about 20 mobile-focused CVEs. The ATT&CK version used is recorded in the
   `attack_version` column.
3. **Merge** the two sources per CVE (union of technique sets, provenance
   kept in `label_sources`).
4. **Join descriptions** from `CIRCL/vulnerability-scores`; CVEs missing
   there are fetched from the
   [Vulnerability-Lookup API](https://vulnerability.circl.lu) as a fallback.
5. **Attach** the CVE2CAPEC derived techniques as `techniques_derived`
   (skippable with `--skip-cve2capec`).
6. **Split** 90/10 into train/test and optionally push to the Hub.

Note that the KEV mappings URL points to a dated release directory; pass
`--kev-mappings-url` (or update the constant) when CTID publishes mappings
for a newer ATT&CK release.

## Dataset schema

| Column | Type | Description |
|--------|------|-------------|
| `id` | str | CVE identifier |
| `title` | str | Vulnerability title |
| `description` | str | English vulnerability description (model input) |
| `exploitation_techniques` | list[str] | CTID exploitation technique(s) |
| `primary_impact` | list[str] | CTID primary impact technique(s) |
| `secondary_impact` | list[str] | CTID secondary impact technique(s) |
| `techniques` | list[str] | Union of all curated techniques (training target) |
| `techniques_derived` | list[str] | CVE2CAPEC weak labels — **not** for training |
| `label_sources` | list[str] | `ctid_cve` and/or `ctid_kev` |
| `attack_version` | str | Enterprise ATT&CK version the IDs are normalized to |

## Known limitations

- **Size**: ~1,250 CVEs supports a proof-of-concept, not a production
  model. Phase 2 (LLM-assisted labeling validated against this gold set)
  addresses this.
- **Selection bias**: both CTID sets over-represent exploited-in-the-wild
  vulnerabilities (the KEV set by construction), so the technique
  distribution is skewed toward remote exploitation of servers compared to
  the full CVE corpus.
- **Version drift**: the 2021 mappings were made against ATT&CK v9;
  normalization fixes revoked IDs but cannot retroactively add
  sub-techniques an analyst working today might have chosen.
- **Inherent task ceiling**: a CVE description describes a flaw, while
  ATT&CK describes attacker behavior around it — even human annotators
  disagree on such mappings. Any model trained on this data should be
  presented as *suggesting candidate techniques* for analyst review, not as
  an authoritative mapping.

## Training (Phase 2)

The trainer is implemented in `vulntrain/trainers/attack_guesser.py`
(`vulntrain-train-attack-classification`):

- The task is **multi-label** (a CVE legitimately maps to several
  techniques): the model trains on the `techniques` column with a sigmoid
  head and binary cross-entropy loss, unlike the single-label CWE trainer.
  Per-label positive weights (`--class-weights`) counter class imbalance.
- Sub-techniques are collapsed to their parent technique at training time
  (the same trick as the CWE ancestor mapping), and the label vocabulary is
  restricted to techniques with at least `--min-examples` (default 5)
  training examples.
- Evaluation reports micro/macro F1 at the 0.5 threshold plus
  **recall@3/recall@5**, the metrics that matter for suggesting candidate
  techniques to an analyst.
- The weak `techniques_derived` column is intentionally ignored by the
  trainer.

Still to do in Phase 2:

- An embedding-similarity baseline (SMET-style, no training required): the
  fine-tuned model has to beat it to justify existing.
- LLM-assisted label expansion, validated against the gold set, to grow
  beyond ~1,200 examples.
