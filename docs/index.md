# VulnTrain documentation

```{toctree}
:hidden:
:caption: Guides

publishing
```

```{toctree}
:hidden:
:caption: Supplementary pages

attack-techniques-dataset
cnvd-severity-improvements
cwe-classification-improvements
hpc
```

<!-- ```{contents} Table of Contents
:depth: 3
``` -->

## Presentation

VulnTrain provides a set of tools to generate diverse AI-ready datasets and train models using comprehensive vulnerability data from [Vulnerability-Lookup](https://vulnerability.circl.lu).
It leverages over one million JSON records from multiple advisory sources to build severity classifiers, description generators, and CWE classifiers.

Models and datasets are published to Hugging Face Hub under the [CIRCL](https://huggingface.co/CIRCL) organization.

### Supported sources

| Source | Language | Description |
|--------|----------|-------------|
| `cvelistv5` | English | CVE Program (enriched with vulnrichment and Fraunhofer FKIE) |
| `github` | English | GitHub Security Advisories |
| `pysec` | English | PySec advisories |
| `csaf_redhat` | English | CSAF Red Hat |
| `csaf_cisco` | English | CSAF Cisco |
| `csaf_cisa` | English | CSAF CISA |
| `cnvd` | Chinese | China National Vulnerability Database |
| `fstec` | Russian | Russian Federal Service for Technical and Export Control (BDU) |

## Installation

```bash
git clone https://github.com/vulnerability-lookup/VulnTrain.git
cd VulnTrain/
poetry install
```

Three types of commands are available:

- **Dataset generation**: Create and prepare datasets from vulnerability sources.
- **Model training**: Train models using the prepared datasets.
- **Model validation**: Evaluate and compare trained models.

## Configuration

Copy `vulntrain/config/conf_sample.py` to `vulntrain/config/conf.py` and fill in the Valkey connection details and tokens. Set the `VulnTrain_CONFIG` environment variable to point to your config file.

For AMD ROCm GPU:

```bash
pip3 install --pre torch torchvision torchaudio --index-url https://download.pytorch.org/whl/nightly/rocm6.4/
```

## Workflows

The full pipeline — regenerating each published dataset, retraining each
published model, and validating the result — is documented in the
dedicated runbook: [Regenerating the published datasets and
models](publishing.md). It includes a per-artifact summary table (which
command updates which Hub repository, and whether its card is pushed
automatically from a template in `vulntrain/cards/` or maintained by
hand).

Task-specific background lives in the supplementary pages:

- [CVE to ATT&CK techniques](attack-techniques-dataset.md) — dataset
  methodology, model evaluation, and the experiment history (metadata
  ablation, derivation-chain rejection, label semantics, bucket-aware
  training).
- [CNVD severity improvements](cnvd-severity-improvements.md) and
  [CWE classification improvements](cwe-classification-improvements.md) —
  the reasoning behind the training options of those models.
- [HPC](hpc.md) — distributed multi-GPU training via SLURM.

## Citation

- Bonhomme, C., & Dulaunoy, A. (2026). Mapping CVEs to MITRE ATT&CK Techniques: A Curated Gold-Set Classifier and the Limits of LLM-Assisted Label Expansion.
  [arXiv](https://arxiv.org/abs/2607.25572)
- Bonhomme, C., & Dulaunoy, A. (2025). VLAI: A RoBERTa-Based Model for Automated Vulnerability Severity Classification. ArXiv, abs/2507.03607.
  [arXiv](https://arxiv.org/abs/2507.03607)


## License

[VulnTrain](https://github.com/vulnerability-lookup/VulnTrain) is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)

~~~
Copyright (c) 2025-2026 Computer Incident Response Center Luxembourg (CIRCL)
Copyright (C) 2025-2026 Cédric Bonhomme - https://github.com/cedricbonhomme
Copyright (C) 2025 Léa Ulusan - https://github.com/3LS3-1F
~~~

