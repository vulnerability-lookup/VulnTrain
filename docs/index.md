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

## What VulnTrain does

VulnTrain turns the vulnerability data collected by
[Vulnerability-Lookup](https://vulnerability.circl.lu) — over one million
advisory records — into AI-ready datasets and trained models. It answers
questions such as: how severe is this vulnerability given only its
description, which CWE does this patch fix, and which MITRE ATT&CK
techniques does this CVE enable.

Everything it produces is published on the Hugging Face Hub under the
[CIRCL](https://huggingface.co/CIRCL) organization.

Work always follows the same three stages, each with its own family of
commands:

1. **Dataset generation** — read the raw advisory records and build a
   dataset (`vulntrain-dataset-*`).
2. **Model training** — fine-tune a base model on that dataset
   (`vulntrain-train-*`).
3. **Validation** — evaluate and compare the trained models
   (`vulntrain-validate-*`, `vulntrain-infer-*`).

Every command accepts `--help`.

## Installation

```bash
git clone https://github.com/vulnerability-lookup/VulnTrain.git
cd VulnTrain/
poetry install
```

For an AMD ROCm GPU, install the matching PyTorch build:

```bash
pip3 install --pre torch torchvision torchaudio --index-url https://download.pytorch.org/whl/nightly/rocm6.4/
```

## Configuration

Copy `vulntrain/config/conf_sample.py` to `vulntrain/config/conf.py` and fill in the Valkey connection details and tokens. Set the `VulnTrain_CONFIG` environment variable to point to your config file.

Most dataset generators read the raw records straight from the Valkey
database of Vulnerability-Lookup, so it must be running. Training and
validation only need the datasets on the Hub.

## Where to go next

- **[Regenerating the published datasets and models](publishing.md)** —
  the runbook, and the best place to start: the exact command line behind
  every dataset and model on the Hub, plus which cards are pushed
  automatically and which are maintained by hand.
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

