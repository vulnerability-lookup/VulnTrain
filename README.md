# VulnTrain

[![Latest release](https://img.shields.io/github/release/vulnerability-lookup/VulnTrain.svg?style=flat-square)](https://github.com/vulnerability-lookup/VulnTrain/releases/latest)
[![License](https://img.shields.io/github/license/vulnerability-lookup/VulnTrain.svg?style=flat-square)](https://www.gnu.org/licenses/gpl-3.0.html)
[![PyPi version](https://img.shields.io/pypi/v/VulnTrain.svg?style=flat-square)](https://pypi.org/project/VulnTrain)


VulnTrain offers a suite of commands to generate diverse AI datasets and train models using
comprehensive vulnerability data from [Vulnerability-Lookup](https://github.com/vulnerability-lookup/vulnerability-lookup).
It harnesses over one million JSON records from all supported advisory sources to build high-quality, domain-specific models.
  
Additionally, data from the ``vulnerability-lookup:meta`` container, including enrichment sources such as vulnrichment and Fraunhofer FKIE,
is incorporated to enhance model quality.

Check out the datasets and models on Hugging Face: 

[![Model on HF](https://huggingface.co/datasets/huggingface/badges/resolve/main/model-on-hf-xl-dark.svg)](https://huggingface.co/CIRCL)

For more information about the use of AI in Vulnerability-Lookup, please refer to the
[user manual](https://www.vulnerability-lookup.org/user-manual/ai/).


## Usage

Install VulnTrain:

```bash
$ pipx install VulnTrain
```

Three types of commands are available:

- **Dataset generation**: Create and prepare datasets.
- **Model training**: Train models using the prepared datasets.
  - Train a model to **classify** vulnerabilities by severity. [![Model on HF](https://huggingface.co/datasets/huggingface/badges/resolve/main/model-on-hf-sm-dark.svg)](https://huggingface.co/CIRCL/vulnerability-severity-classification-roberta-base)
  - Train a model for **text generation** to assist in writing vulnerability descriptions [![Model on HF](https://huggingface.co/datasets/huggingface/badges/resolve/main/model-on-hf-sm-dark.svg)](https://huggingface.co/CIRCL/vulnerability-description-generation-gpt2#how-to-get-started-with-the-model)
- **Model validation**: Assess the performance of trained models (validations, benchmarks, etc.).


Check out the [documentation](docs/) for more information.


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
Copyright (c) 2025 Computer Incident Response Center Luxembourg (CIRCL)
Copyright (C) 2025 Cédric Bonhomme - https://github.com/cedricbonhomme
Copyright (C) 2025 Léa Ulusan - https://github.com/3LS3-1F
~~~

