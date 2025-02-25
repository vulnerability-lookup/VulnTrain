# Changelog

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