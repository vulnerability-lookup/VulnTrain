# AGENTS.md

Instructions for AI coding agents working on VulnTrain, whatever the tool.

## Rules for AI agents

These rules come from the "Spirit of the project" and "Use of AI and LLM tools"
sections of [CONTRIBUTING.md](CONTRIBUTING.md). They are mandatory. Read CONTRIBUTING.md
too: it is the reference, and it wins if the two files ever disagree.

- **Keep the spirit of the project.** Results must be reproducible: a figure in the
  documentation or in a model card comes from a command that can be run again, never
  from an estimate. Keep the three stages (dataset, training, validation) and their
  commands separate. Never write a token or a connection detail to a tracked file.
  Add no dependency without a justification.
- **Never publish.** Do not push a dataset or a model to the Hugging Face Hub, and do
  not make a release: use `--no-push` for a run you start. Publishing is the human's
  decision.
- **Work from an issue.** A change should follow an issue that explains its rationale
  (the problem, why it matters, the proposed approach); only small fixes can skip it.
- **Stay in scope.** Keep changes minimal and focused on the task. Do not reformat,
  rename, or rewrite unrelated code or comments.
- **Check what you produce.** Run `poetry run mypy vulntrain/` and
  `poetry run isort --check vulntrain/` before handing your work over, and say plainly
  what you could not verify: a training run you did not start, a metric you did not
  measure. The human you work with must read, understand and test every change before
  submitting it: vibe-coded pull requests are closed.
- **Make it explainable.** Explain every change to the human you work with. Reviewers
  may ask them to explain any part of it, and a pull request whose author cannot is
  closed. Do not write their answers to review comments for them to paste.
- **A human reviews and submits.** Never open a pull request or an issue on your own;
  the decision is the human's, after they have reviewed your work.
- **Report only what was reproduced.** When you help write an issue, the human must
  have reproduced the problem. Never present an unverified finding, or a metric that
  was not measured, as a confirmed one.
- **Say so.** End every commit you author with a `Co-Authored-By` trailer naming the
  model and its version, for example:

  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  ```

  When you draft a pull request description, follow
  [.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md) and keep all its
  sections, and mention that a significant part of the change was generated with an AI
  tool. Never tick the box "I have read, understood and tested every change": it is
  the human's own statement, leave it for them.
- **One summary for tools.** [ai-policy.yaml](ai-policy.yaml) is a machine-readable
  summary of the rules on AI. When you change these rules, update it too. If the two
  disagree, CONTRIBUTING.md wins.

## Project Overview

VulnTrain generates AI datasets and trains models from vulnerability data sourced via Vulnerability-Lookup. It processes 1M+ JSON vulnerability records (CVEs, GitHub advisories, CSAF, PySecDB, CNVD) to build severity classifiers, description generators, and CWE classifiers. Models and datasets are published to Hugging Face Hub under the CIRCL organization.

## Build & Development

**Package manager**: Poetry 2.0+ with Python 3.12–3.15.

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
| `vulntrain-train-severity-certfr-classification` | Train severity classifier for CERT-FR (French) data |
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
├── data/            # Package data shipped with vulntrain
│   └── deep_child_to_ancestor.json  # CWE child→ancestor mapping used by the CWE trainer
├── trainers/        # HF Transformers Trainer-based training
│   ├── classify_severity.py       # Severity classification (CVSS→Low/Med/High/Critical)
│   ├── classify_severity_cnvd.py  # CNVD-specific severity classification
│   ├── generation_description.py  # GPT-2 description generation
│   └── cwe_guesser_patches.py     # CWE classification with weighted loss
├── validators/      # Model evaluation and benchmarking
│   ├── severity.py, summarize.py  # Per-task validators
│   ├── evaluation.py              # Comprehensive evaluation framework
│   └── benchmark_models.py        # Model comparison
└── utils.py         # CVSS extraction (v2/v3/v4), CPE parsing, markdown stripping
```

One-off CWE mapping generation scripts and their input/output JSON files live in `tools/cwe/` (see `tools/cwe/README.md` for the pipeline). `tools/dataset/check_split_leakage.py` checks a published dataset revision for train/test leakage (see `tools/dataset/README.md`).

**Key design points**:
- `VulnExtractor` (in `datasets/create_dataset.py`) connects to a Valkey (Redis-compatible) database holding raw vulnerability JSON and supports sources: `cvelistv5`, `github`, `csaf_redhat`, `csaf_cisco`, `csaf_cisa`, `pysec`, `cnvd`, `fstec`, `certfr_alerte`, `certfr_avis`. CERT-FR bulletins have no severity of their own and are labelled with the highest CVSS score of their linked CVEs (bulletins with 1–10 CVEs only).
- Trainers map CVSS scores to severity labels and support configurable score strategies (first, latest, mean).
- All trainers use the Hugging Face `Trainer` API with carbon emissions tracking via CodeCarbon.
- Distributed multi-GPU training is supported via SLURM (see `etc/run_vulntrain.slurm`).

## Code Style

- **Type hints**: Full typing expected; mypy runs in strict mode (`check_untyped_defs`, `strict_optional`, `no_implicit_optional`, `warn_unreachable`).
- **Import sorting**: isort with Black-compatible profile.
- **License**: GPLv3. All source files should preserve the existing license headers.
