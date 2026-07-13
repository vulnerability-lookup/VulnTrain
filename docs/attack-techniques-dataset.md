# CVE → MITRE ATT&CK techniques dataset

This page documents the methodology behind the
[CIRCL/vulnerability-attack-techniques](https://huggingface.co/datasets/CIRCL/vulnerability-attack-techniques)
dataset and the design decisions that led to it. The goal (tracked in
[VulnTrain issue #6](https://github.com/vulnerability-lookup/VulnTrain/issues/6))
is to train a model that suggests MITRE ATT&CK techniques from a
vulnerability description: CVSS tells you *how bad* a vulnerability is, CWE
tells you *what kind of flaw* it is, ATT&CK tells defenders *what adversary
behavior to expect and detect*. Very few public models cover that gap.

## Workflow at a glance

The full pipeline, in the order the commands are meant to be run (each step
is detailed in its own section below):

```bash
# 1. Build the curated dataset from the MITRE CTID gold mappings
vulntrain-dataset-attack-generation --output-dir ./attack-dataset       # dry run, local only
vulntrain-dataset-attack-generation --push --repo-id CIRCL/vulnerability-attack-techniques

# 2. Train the multi-label classifier (GPU recommended)
vulntrain-train-attack-classification --base-model roberta-base \
  --repo-id CIRCL/vulnerability-attack-technique-classification-roberta-base

# 3. Evaluate: the trained model must beat the zero-shot similarity baseline
vulntrain-validate-attack-classification --method similarity
vulntrain-validate-attack-classification --method classifier \
  --model CIRCL/vulnerability-attack-technique-classification-roberta-base

# 4. Grow the dataset with LLM-assisted labeling — local Ollama model (no
#    API key) or Claude; validate agreement against the gold set BEFORE expanding
vulntrain-dataset-attack-llm-labeling --mode validate --backend ollama --model qwen3.6:35b
vulntrain-dataset-attack-llm-labeling --mode expand --backend ollama --model qwen3.6:35b \
  --sample-n 2000 --push --repo-id CIRCL/vulnerability-attack-techniques-llm

# 5. Retrain on gold + LLM-labeled data and re-run step 3
```

Steps 1–3 are done and published; step 4 is implemented and awaiting its
first validated run; step 5 follows from its results. Source files (CTID
mappings, ATT&CK STIX data, CVE2CAPEC databases) are cached in
`~/.cache/vulntrain`.

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
which 66 have at least 5 examples (57 once sub-techniques are collapsed to
their parent, which is what the trainer uses as its label vocabulary).

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
  instead. That SMET-style similarity ranking is exactly what
  `vulntrain-validate-attack-classification --method similarity` implements
  as the zero-shot baseline (see Training below).

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

- **Size**: ~1,200 CVEs supports a proof-of-concept, not a production
  model. LLM-assisted label expansion (see below), validated against this
  gold set, addresses this.
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

The fine-tuned classifier and a zero-shot similarity baseline (SMET-style —
rank techniques by cosine similarity between the description embedding and
the official ATT&CK technique name+description, no training involved) are
evaluated with the same protocol by
`vulntrain-validate-attack-classification`
(`vulntrain/validators/attack_guesser.py`): both report the same recall@k
and MRR on the same test split and label vocabulary, so the numbers are
directly comparable. The fine-tuned model has to beat the zero-shot
baseline to justify existing.

### Model results (Phase 2)

The first trained model,
[CIRCL/vulnerability-attack-technique-classification-roberta-base](https://huggingface.co/CIRCL/vulnerability-attack-technique-classification-roberta-base)
(roberta-base, 57-technique vocabulary), roughly doubles the zero-shot
baseline on every ranking metric:

| Metric | Zero-shot baseline | Fine-tuned model |
|--------|-------------------|------------------|
| recall@3 | 0.257 | 0.482 |
| recall@5 | 0.322 | 0.686 |
| recall@10 | 0.491 | 0.842 |
| MRR | 0.397 | 0.620 |

So the supervised approach is justified even on ~1,100 training examples.
The remaining weakness is rare-technique performance (macro-F1 0.20), which
is what label expansion targets.

## LLM-assisted label expansion (Phase 2)

`vulntrain/datasets/attack_llm_labeler.py`
(`vulntrain-dataset-attack-llm-labeling`) grows the training set beyond the
~1,200 curated CVEs by having an LLM label additional CVEs with the **same**
CTID methodology (exploitation technique / primary impact / secondary
impact), so the output stays schema-compatible with the gold set.

Two backends, selected with `--backend`:

- `ollama` (no API key, no per-token cost): labels with a local model served
  by an [Ollama](https://ollama.com) instance — e.g. Qwen — using Ollama
  structured outputs. Set `--model` (default `qwen3`; e.g. `qwen3:32b`) and,
  if the server is not local, `--ollama-url`.
- `anthropic`: labels with Claude via the Anthropic API. Requires an API key
  exported as `ANTHROPIC_API_KEY` (create one at
  [platform.claude.com](https://platform.claude.com); note that a Claude Max
  subscription does **not** include API access — it is billed separately).

The system prompt is identical for every CVE — the methodology, the full
active enterprise ATT&CK technique catalog (from the STIX data), and a set
of diverse few-shot examples drawn from the gold set — so both backends'
prompt-prefix caching keeps all but the first request cheap. The model
returns a structured mapping (constrained to the label schema on both
backends); hallucinated or out-of-catalog technique IDs are dropped, and the
Ollama backend retries on malformed output.

The `validate` gate matters most with a local model: it tells you
objectively whether the chosen Ollama model agrees with the analysts well
enough to trust, or whether the gap justifies paying for the API.

**Validate before trusting expansion.** Run the `validate` mode first: it
labels a held-out slice of the *gold* set and reports agreement
(precision/recall/F1 at the parent-technique level) between the model and
the analysts.

```bash
# Local model via Ollama (no API key):
vulntrain-dataset-attack-llm-labeling --mode validate --backend ollama --model qwen3.6:35b

# Or Claude via the Anthropic API:
export ANTHROPIC_API_KEY=sk-ant-...
vulntrain-dataset-attack-llm-labeling --mode validate --backend anthropic
```

Only if that agreement is comparable to inter-analyst agreement on ATT&CK
mappings should you scale up. The `expand` mode then labels a sample of
CVEs (from `CIRCL/vulnerability-scores` by default, excluding gold CVEs) and
writes a dataset with `label_source = ["llm"]` plus the backend/model ID and
its justification comment per row:

```bash
vulntrain-dataset-attack-llm-labeling --mode expand --backend ollama --model qwen3.6:35b \
  --sample-n 2000 --push --repo-id CIRCL/vulnerability-attack-techniques-llm \
  --agreement-note "f1_micro 0.61 on the 121-CVE test split"
```

Each run **appends the backend/model slug to `--repo-id`** (so the example
above pushes to `…-llm-ollama-qwen3.6-35b`) and writes a dataset card
recording the labeling model, the CVE count, and — via `--agreement-note` —
the validation score. This keeps multiple test runs (one per model)
distinguishable rather than overwriting one another; the exact model is also
stored per row in the `llm_model` column. Pass `--no-model-suffix` to push to
`--repo-id` verbatim.

Keep the LLM-labeled rows in a separate provenance tier: merge them with the
gold set for training, but always retain the `label_sources` column so
consumers can filter back to gold-only, and **publish the measured
validation agreement on the expanded dataset card** (the `--agreement-note`
flag does exactly this) so the labels' quality is documented rather than
assumed.

Still to do:

- **Stratify the expansion sample by CWE** so it isn't dominated by the most
  common weakness classes (XSS, SQLi); the current `expand` mode samples
  CVEs without stratification.
- Retrain the classifier on the gold + LLM-labeled union and re-run
  `vulntrain-validate-attack-classification` to confirm the expansion
  improves rare-technique recall.
