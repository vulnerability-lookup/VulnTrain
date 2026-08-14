# VulnTrain

[![Latest release](https://img.shields.io/github/release/vulnerability-lookup/VulnTrain.svg?style=flat-square)](https://github.com/vulnerability-lookup/VulnTrain/releases/latest)
[![License](https://img.shields.io/github/license/vulnerability-lookup/VulnTrain.svg?style=flat-square)](https://www.gnu.org/licenses/gpl-3.0.html)
[![PyPi version](https://img.shields.io/pypi/v/VulnTrain.svg?style=flat-square)](https://pypi.org/project/VulnTrain)


VulnTrain turns the vulnerability data collected by
[Vulnerability-Lookup](https://github.com/vulnerability-lookup/vulnerability-lookup)
into AI datasets and trained models. It processes over one million advisory records
(CVE, GitHub advisories, CSAF, PySecDB, CNVD, FSTEC) to answer questions such as:

- How severe is this vulnerability, given only its description?
- Which CWE does this patch fix?
- Which MITRE ATT&CK techniques does this CVE enable?

All resulting datasets and models are published on Hugging Face:

[![Model on HF](https://huggingface.co/datasets/huggingface/badges/resolve/main/model-on-hf-xl-dark.svg)](https://huggingface.co/CIRCL)


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

## Documentation

Full documentation — configuration, dataset generation, training recipes and
methodology — is available at
https://vulnerability-lookup.github.io/VulnTrain

For more information about the use of AI in Vulnerability-Lookup, please refer to the
[user manual](https://www.vulnerability-lookup.org/user-manual/ai/).


## Usage

Every task follows the same three stages, each with its own command.

**1. Build a dataset** from the vulnerability sources and push it to the Hub:

```bash
vulntrain-dataset-generation --sources cvelistv5,github,csaf_redhat,pysec \
  --repo-id CIRCL/vulnerability-scores
```

**2. Train a model** on that dataset (trainers push to the Hub by default; use
`--no-push` for a local run):

```bash
vulntrain-train-severity-classification --base-model roberta-base \
  --dataset-id CIRCL/vulnerability-scores \
  --repo-id CIRCL/vulnerability-severity-classification-roberta-base
```

**3. Validate** the trained model:

```bash
vulntrain-validate-severity-classification
```

### Available tasks

| Task | Train with | Published model |
|------|------------|-----------------|
| Severity classification | `vulntrain-train-severity-classification` | [`…severity-classification-roberta-base`](https://huggingface.co/CIRCL/vulnerability-severity-classification-roberta-base) |
| Severity classification (Chinese, CNVD) | `vulntrain-train-severity-cnvd-classification` | [`…severity-classification-chinese-macbert-base`](https://huggingface.co/CIRCL/vulnerability-severity-classification-chinese-macbert-base) |
| CWE classification from patches | `vulntrain-train-cwe-classification` | [`…cwe-classification-modernbert-base`](https://huggingface.co/CIRCL/vulnerability-cwe-classification-modernbert-base) |
| CVE → ATT&CK techniques | `vulntrain-train-attack-classification` | [`…attack-technique-classification-roberta-base`](https://huggingface.co/CIRCL/vulnerability-attack-technique-classification-roberta-base) |
| CVE → ATT&CK techniques (bi-encoder) | `vulntrain-train-attack-biencoder` | [`…attack-technique-biencoder`](https://huggingface.co/CIRCL/vulnerability-attack-technique-biencoder) |
| Description generation | `vulntrain-train-description-generation` | `…description-generation-gpt2*` |

Every command accepts `--help`. The exact command lines used to regenerate each
published artifact are in the
[runbook](https://vulnerability-lookup.github.io/VulnTrain/publishing.html).


## How to cite

For the severity classification work:

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

For the ATT&CK technique mapping work:

Bonhomme, C., & Dulaunoy, A. (2026). Mapping CVEs to MITRE ATT&CK Techniques: A Curated Gold-Set Classifier and the Limits of LLM-Assisted Label Expansion. https://doi.org/10.48550/arXiv.2607.25572

```bibtex
@misc{bonhomme2026mappingcvesmitreattck,
    title={Mapping CVEs to MITRE ATT&CK Techniques: A Curated Gold-Set Classifier and the Limits of LLM-Assisted Label Expansion},
    author={Cédric Bonhomme and Alexandre Dulaunoy},
    year={2026},
    eprint={2607.25572},
    archivePrefix={arXiv},
    primaryClass={cs.CR},
    url={https://arxiv.org/abs/2607.25572},
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

## Funding

[AIPITCH](https://www.linkedin.com/company/aipitch)
(AI-Powered Innovative Toolkit for Cybersecurity Hubs) is a co-funded EU project
supported by the European Cybersecurity Competence Centre (ECCC) under the
DIGITAL-ECCC-2024-DEPLOY-CYBER-06-ENABLINGTECH program and
[CIRCL](https://www.circl.lu).

The project brings together an international consortium to develop AI-based tools
that enhance the capabilities of operational cybersecurity teams.
These tools are designed to support critical services, with a focus on national
security teams, while also being applicable to internal security teams in
companies and institutions.
