# Changelog

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