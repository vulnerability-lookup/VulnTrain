# VulnTrain

[![Latest release](https://img.shields.io/github/release/vulnerability-lookup/VulnTrain.svg?style=flat-square)](https://github.com/vulnerability-lookup/VulnTrain/releases/latest)
[![License](https://img.shields.io/github/license/vulnerability-lookup/VulnTrain.svg?style=flat-square)](https://www.gnu.org/licenses/gpl-3.0.html)
[![PyPi version](https://img.shields.io/pypi/v/VulnTrain.svg?style=flat-square)](https://pypi.org/project/VulnTrain)


VulnTrain offers a suite of commands to generate diverse AI datasets and train models using
comprehensive vulnerability data from [Vulnerability-Lookup](https://github.com/vulnerability-lookup/vulnerability-lookup).
It harnesses over one million JSON records from all supported advisory sources (CVE, GitHub advisories, CSAF, PySecDB, CNVD) to build high-quality, domain-specific models.

Additionally, data from the ``vulnerability-lookup:meta`` container, including enrichment sources such as vulnrichment and Fraunhofer FKIE,
is incorporated to enhance model quality.

Check out the datasets and models on Hugging Face:

[![Model on HF](https://huggingface.co/datasets/huggingface/badges/resolve/main/model-on-hf-xl-dark.svg)](https://huggingface.co/CIRCL)

For more information about the use of AI in Vulnerability-Lookup, please refer to the
[user manual](https://www.vulnerability-lookup.org/user-manual/ai/).


## Installation

```bash
pipx install VulnTrain
```

For development:

```bash
git clone https://github.com/vulnerability-lookup/VulnTrain.git
cd VulnTrain/
poetry install
```


## Usage

Three types of commands are available:

- **Dataset generation**: Create and prepare datasets from vulnerability sources.
- **Model training**: Train models using the prepared datasets.
- **Model validation**: Assess the performance of trained models (validations, benchmarks, etc.).

### CLI commands

| Command | Purpose |
|---------|---------|
| `vulntrain-dataset-generation` | Generate datasets from vulnerability sources |
| `vulntrain-train-severity-classification` | Train severity classifier (RoBERTa/DistilBERT) |
| `vulntrain-train-severity-cnvd-classification` | Train severity classifier for CNVD data |
| `vulntrain-train-description-generation` | Train GPT-2 vulnerability description generator |
| `vulntrain-train-cwe-classification` | Train CWE classifier from patches |
| `vulntrain-validate-severity-classification` | Validate severity model |
| `vulntrain-validate-text-generation` | Validate text generation model |

### Models

- Severity classification: [![Model on HF](https://huggingface.co/datasets/huggingface/badges/resolve/main/model-on-hf-sm-dark.svg)](https://huggingface.co/CIRCL/vulnerability-severity-classification-roberta-base)
- Description generation: [![Model on HF](https://huggingface.co/datasets/huggingface/badges/resolve/main/model-on-hf-sm-dark.svg)](https://huggingface.co/CIRCL/vulnerability-description-generation-gpt2#how-to-get-started-with-the-model)


## Distributed training on HPC clusters

VulnTrain supports distributed multi-GPU training via SLURM, making it suitable for
EuroHPC-style GPU clusters. See the [HPC documentation](docs/hpc.md) for
Conda environment setup, single-node and multi-node SLURM job scripts, and NCCL configuration.


## Documentation

Check out the full [documentation](docs/) for detailed usage instructions, dataset generation examples, and training recipes.


## How to cite

Bonhomme, C., & Dulaunoy, A. (2025). VLAI: A RoBERTa-Based Model for Automated Vulnerability Severity Classification (Version 1.4.0) [Computer software]. https://doi.org/10.48550/arXiv.2507.03607

```bibtex
@misc{bonhomme2025vlai,
    title={VLAI: A RoBERTa-Based Model for Automated Vulnerability Severity Classification},
    author={Cédric Bonhomme and Alexandre Dulaunoy},
    year={2025},
    eprint={2507.03607},
    archivePrefix={arXiv},
    primaryClass={cs.CR}
}
```


## License

[VulnTrain](https://github.com/vulnerability-lookup/VulnTrain) is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)

~~~
Copyright (c) 2025-2026 Computer Incident Response Center Luxembourg (CIRCL)
Copyright (C) 2025-2026 Cédric Bonhomme - https://github.com/cedricbonhomme
Copyright (C) 2025 Léa Ulusan - https://github.com/3LS3-1F
~~~
