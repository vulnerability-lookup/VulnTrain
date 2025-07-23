# Changelog

## Release 1.5.0 (not-yet-released)

### News

- A documentation is now available.
  ca6d6e2c5f64b7cb8c021a8dafe38a342c71464b

### Changes

- Model generation: Added a boolean parameter in map_cvss_to_severity
  in order to switch between using the first non-null CVSS score
  or the mean of all available CVSS scores.
  ff6616e1023f02836ecb26e50e0c315ec6558895
- Dataset generation: Removed useless keys in extract_cnvd
  b7d6948c2130d004d3df037d3db82a219c8a206e


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