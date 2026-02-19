# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VulnTrain generates AI datasets and trains models from vulnerability data sourced via Vulnerability-Lookup. It processes 1M+ JSON vulnerability records (CVEs, GitHub advisories, CSAF, PySecDB, CNVD) to build severity classifiers, description generators, and CWE classifiers. Models and datasets are published to Hugging Face Hub under the CIRCL organization.

## Build & Development

**Package manager**: Poetry 2.0+ with Python 3.11–3.14.

```bash
poetry install              # Install dependencies
poetry install --with docs  # Include Sphinx documentation deps
```

**Configuration**: Set `VulnTrain_CONFIG` env var to point to a config file (copy `vulntrain/config/conf_sample.py` to `vulntrain/config/conf.py` and fill in Valkey connection details and tokens). Falls back to `conf_sample.py` if unset.

**Type checking and linting**:
```bash
poetry run mypy vulntrain/     # Type checking (strict mode, see pyproject.toml)
poetry run isort vulntrain/    # Import sorting (Black profile)
```

**Documentation**:
```bash
cd docs && make html    # Build Sphinx docs (requires docs dependency group)
```

## CLI Commands

All commands are installed as entry points via `poetry install`:

| Command | Purpose |
|---------|---------|
| `vulntrain-dataset-generation` | Generate datasets from vulnerability sources |
| `vulntrain-train-severity-classification` | Train RoBERTa/DistilBERT severity classifier |
| `vulntrain-train-severity-cnvd-classification` | Train severity classifier for CNVD data |
| `vulntrain-train-description-generation` | Train GPT-2 vulnerability description generator |
| `vulntrain-train-cwe-classification` | Train CWE classifier from patches |
| `vulntrain-validate-severity-classification` | Validate severity model |
| `vulntrain-validate-text-generation` | Validate text generation model |

## Architecture

The codebase follows a pipeline: **Data Extraction → Dataset Creation → Training → Validation → Hub Push**.

```
vulntrain/
├── config/          # Dynamic config loading via VulnTrain_CONFIG env var
├── datasets/        # Dataset generation from Valkey DB
│   ├── create_dataset.py      # VulnExtractor: main dataset builder
│   └── cwe-guesser-dataset.py # CWE dataset with Git diffs (async GitHub API)
├── trainers/        # HF Transformers Trainer-based training
│   ├── classify_severity.py       # Severity classification (CVSS→Low/Med/High/Critical)
│   ├── classify_severity_cnvd.py  # CNVD-specific severity classification
│   ├── generation_description.py  # GPT-2 description generation
│   ├── cwe_guesser_patches.py     # CWE classification with weighted loss
│   └── hierarchy.py               # CWE hierarchy utilities + JSON mappings
├── validators/      # Model evaluation and benchmarking
│   ├── severity.py, summarize.py  # Per-task validators
│   ├── evaluation.py              # Comprehensive evaluation framework
│   └── benchmark_models.py        # Model comparison
└── utils.py         # CVSS extraction (v2/v3/v4), CPE parsing, markdown stripping
```

**Key design points**:
- `VulnExtractor` (in `datasets/create_dataset.py`) connects to a Valkey (Redis-compatible) database holding raw vulnerability JSON and supports sources: `cvelistv5`, `github`, `csaf_redhat`, `csaf_cisco`, `csaf_cisa`, `pysec`, `cnvd`.
- Trainers map CVSS scores to severity labels and support configurable score strategies (first, latest, mean).
- All trainers use the Hugging Face `Trainer` API with carbon emissions tracking via CodeCarbon.
- Distributed multi-GPU training is supported via SLURM (see `etc/run_vulntrain.slurm`).

## Code Style

- **Type hints**: Full typing expected; mypy runs in strict mode (`check_untyped_defs`, `strict_optional`, `no_implicit_optional`, `warn_unreachable`).
- **Import sorting**: isort with Black-compatible profile.
- **License**: GPLv3. All source files should preserve the existing license headers.
