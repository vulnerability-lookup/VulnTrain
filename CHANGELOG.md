# Changelog

## Release 3.1.0 (2026-04-06)

### What's New

#### Datasets

- **Source field**: each vulnerability entry now includes a `source` field identifying its origin (cvelistv5, github, pysec, cnvd, csaf_*).
- **Dynamic dataset card for multi-source datasets**: when generating a dataset from multiple sources (e.g., `--sources cvelistv5,github,csaf_redhat,csaf_cisco,csaf_cisa,pysec`), a dataset card is now automatically generated with a per-source breakdown table showing entry counts and percentages.

#### Training

- **Per-class metrics for severity trainer** (`classify_severity.py`): `compute_metrics` now reports precision, recall, and F1 per class (Low/Medium/High/Critical) alongside overall accuracy and macro F1.
- **Best model checkpoint selection** (`classify_severity.py`): model selected by accuracy instead of eval_loss, `save_total_limit` increased from 2 to 3.

### Changes

- Moved all HuggingFace card templates (dataset cards, model cards) to a dedicated `vulntrain/cards/` directory.
- Updated dependencies.


## Release 3.0.0 (2026-04-03)

### What's New

#### CNVD Severity Trainer

- **Data leakage fix**: new `deduplicate_split()` function groups entries by description text before splitting, preventing identical descriptions from appearing in both train and test sets. CNVD reuses boilerplate descriptions across different vulnerability IDs, which previously contaminated 15.6% of the test set.
- **Per-class metrics**: `compute_metrics` now reports precision, recall, and F1 per class (Low/Medium/High) alongside overall accuracy and macro F1 at each evaluation epoch.
- **Class weighting options**: new `--class-weights` flag (`none`, `sqrt`, `balanced`, `focal`) for experimenting with class imbalance strategies. Includes a `FocalLossTrainer` implementation (Lin et al., 2017). Defaults to uniform loss after experiments showed all weighting strategies degrade Medium recall disproportionately.
- **Best model checkpoint selection**: `metric_for_best_model` set to `accuracy` (was defaulting to `eval_loss`), `save_total_limit` increased from 2 to 3.
- **Dynamic model card**: model card is now a template populated with actual eval metrics from `trainer.evaluate()` after each training run. Documents per-class metrics, training configuration, and known limitations.

#### CNVD Dataset

- **CVE cross-references**: `extract_cnvd` now extracts the `cve_id` field from `cves.cve.cveNumber`, enabling cross-referencing with CVE equivalents (~81% of entries).
- **Dataset card**: new dataset card documenting severity distribution, CVE overlap rates, coverage decline post-RMSV (94% published in 2015 to 4% in 2023), and duplicate description caveat.

#### Validation

- **CNVD severity model comparison validator**: new `validators/severity_cnvd.py` script to evaluate old and new models side by side on the same deduplicated test set, reporting per-class metrics, confusion matrices, and summary deltas.

### Fixes

- **CodeCarbon tracker hang**: replaced `@track_emissions` decorator with explicit `EmissionsTracker` scoped to `trainer.train()` only. Removed `push_to_hub=True` from `TrainingArguments` which caused the trainer to upload internally before returning. Applied to both `classify_severity_cnvd.py` and `classify_severity.py`.

### Documentation

- Added technical report: `docs/cnvd-severity-improvements.md`.
- Improved `docs/index.md` with configuration section, CNVD-specific details, and validator usage.

### Acknowledgments

Thanks to [Eric Romang](https://github.com/eromang) for his thorough independent analysis ([VulnTrain#19](https://github.com/vulnerability-lookup/VulnTrain/issues/19)) that prompted these improvements.


## Release 2.2.0 (2026-02-19)

### What's New

#### Training

- **New CLI options for severity classification trainer** (`classify_severity.py`):
  - `--no-codecarbon`: Disable CodeCarbon emissions tracking.
  - `--no-push`: Disable pushing the model and tokenizer to Hugging Face Hub.
  - `--no-cache`: Disable cache for the model during training.


## Release 2.1.0 (2025-11-18)

### What's New

#### Datasets

- **CWE/Patch dataset improvements**: Considered more fields to find vulnerability patches. Asynchronous requests to GitHub are now less aggressive.
- **CWE Guesser dataset**:
  - Now uses the new vulnerability endpoint of Vulnerability-Lookup.
  - References in security advisories without the `patch` tag are also considered.
  - Repo ID is now a configurable parameter in the dataset generation script.
- **URL handling improvements**:
  - `normalize_patch_url` function improved for better patch URL processing.
  - URLs with fragments are now properly handled.
- **Concurrency**: Reduced the number of default concurrent requests to 12 to avoid overloading external services.

#### Dependencies

- Updated Python dependencies, including **PyTorch bump from 2.7.1 to 2.8.0**.
- General dependency updates across the project.

#### Miscellaneous

- Minor code improvements and style updates (reformatted with `black`).


## Release 2.0.0 (2025-09-05)

### News

- **Dataset generation:** Introduced a new script to build datasets of structured vulnerabilities enriched with CWE identifiers and corresponding patches.
  Each entry now includes the Git commit message and the full diff (Base64-encoded).
  [#10](https://github.com/vulnerability-lookup/VulnTrain/pull/10) by @3LS3-1F
- **Model generation:** Added a new trainer for predicting CWE classifications from vulnerability descriptions and associated patches (commit messages).
  [#10](https://github.com/vulnerability-lookup/VulnTrain/pull/10) by @3LS3-1F

Related resources shared via Hugging Face: https://huggingface.co/collections/CIRCL/vlai-for-cwe-guessing-68bab22e3d71b513146d13b3

### Changes

- Improved documentation and reorganized modules for better clarity and maintainability.
- Updated dependencies to their latest stable versions.


## Release 1.5.0 (2025-07-25)

### News

- **Dataset generation:** Associating Git Fixes with Common Weakness Enumerations (CWEs) found
  in security advisories.
  ((#4)[https://github.com/vulnerability-lookup/VulnTrain/issues/4])
- A documentation is now available.
  ([8a345ca](https://github.com/vulnerability-lookup/VulnTrain/commit/ca6d6e2c5f64b7cb8c021a8dafe38a342c71464b))

### Changes

- Model generation: Added a boolean parameter in map_cvss_to_severity
  in order to switch between using the first non-null CVSS score
  or the mean of all available CVSS scores.
  ([ff6616e](https://github.com/vulnerability-lookup/VulnTrain/commit/ff6616e1023f02836ecb26e50e0c315ec6558895))
- Dataset generation: Removed useless keys in extract_cnvd
- ([b7d694](https://github.com/vulnerability-lookup/VulnTrain/commit/b7d6948c2130d004d3df037d3db82a219c8a206e))


## Release 1.4.0 (2025-07-01)

### News

This version adds support for creating new AI-ready datasets
based on the China National Vulnerability Database (CNVD).
It also introduces a new training module designed to classify
vulnerabilities using text classification models tailored for CNVD data.
By [Léa](https://github.com/3LS3-1F)


## Release 1.3.1 (2025-04-28)

### Changes

- Updated dependencies and fixed issues due to changes in transformers.


## Release 1.3.0 (2025-04-28)

### Changes

- Updated dependencies.


- ## Release 1.2.0 (2025-03-11)

### Changes

- Dataset generation: CVSS are now extracted from GitHub and PySec security advisories.
- Dataset generation: CVSS, CPE, title and description (summary) are now extracted from CSAF document.


## Release 1.1.0 (2025-02-27)

### News

- Trainers: Support of roberta-base for the text classifier with improved
  settings for TrainingArguments.
- Validators: Validator for severity classification.


## Release 1.0.0 (2025-02-25)

### News

- Introduced a new trainer to automatically classify vulnerabilities based on their descriptions,  
  even when CVSS scores are unavailable.  
- Added CVSS parsing to the dataset generation script.  

### Changes

- Refactored the project structure for better organization.  
- Improved CPE parsing.  
- Enhanced the dataset generation script.  
- Optimized the trainer for text generation on vulnerability descriptions.  
- Improved command-line argument parsing.  
- Improved the process of pushing the tokenizer and trainer to Hugging Face.  


## Release 0.5.1 (2025-02-22)

Fixed configuration module name.


## Release 0.5.0 (2025-02-21)

Added support of configuration file.


## Release 0.4.0 (2025-02-21)

The dataset generation step now uses data from GitHub Advisories,
and the VulnExtractor cleans the summary and details fields.


## Release 0.3.0 (2025-02-20)

### News

Dataset generation: allow specifying a commit message when uploading to Hugging Face.

Validation: Added a simple validation script for model optimized for text generation. The script is
able to pull a model and send tasks via a Pipeline

### Changes

For the training step: added the choices of model: gpt2, distilgpt2,
meta-llama/Llama-3.3-70B-Instruct, distilbert-base-uncased

Various improvements to the command line parsing.


## Release 0.2.0 (2025-02-20)

### News

Added a trainer.
Experimenting distilbert-base-uncased (AutoModelForMaskedLM) and gpt2 (AutoModelForCausalLM).
The goal is to generate text.

### Changes

Various improvements to the dataset generator. And added a command line parser.


## Release 0.1.0 (2025-02-19)

First release with upload of datasets to HuggingFace.

Datasets are build based on NIST data with enrichment from FKIE and vulnrichment