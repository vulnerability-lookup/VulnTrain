# VulnTrain documentation

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

## Datasets

Ensure that the ``huggingface_hub`` package is installed:

```bash
pipx install huggingface_hub
```

Then log in to Hugging Face:

```bash
hf auth login
```

Then ensure that the Valkey database of Vulnerability-Lookup is running.


### Vulnerability severity scores

Example: Generate [CIRCL/vulnerability-scores](https://huggingface.co/datasets/CIRCL/vulnerability-scores) dataset

```bash
vulntrain-dataset-generation --sources cvelistv5,github,csaf_redhat,csaf_cisco,csaf_cisa,pysec --repo-id=CIRCL/vulnerability-scores
```

Example: Generate [CIRCL/Vulnerability-CNVD](https://huggingface.co/datasets/CIRCL/Vulnerability-CNVD) dataset

```bash
vulntrain-dataset-generation --sources cnvd --repo-id=CIRCL/Vulnerability-CNVD
```

The CNVD dataset includes a `cve_id` field cross-referencing CVE equivalents (~81% of entries).
See the [dataset card](https://huggingface.co/datasets/CIRCL/Vulnerability-CNVD) for details on coverage, severity distribution, and known caveats.

Example: Generate [CIRCL/Vulnerability-FSTEC](https://huggingface.co/datasets/CIRCL/Vulnerability-FSTEC) dataset (Russian Federal Service for Technical and Export Control / BDU)

```bash
vulntrain-dataset-generation --sources fstec --repo-id=CIRCL/Vulnerability-FSTEC
```

The FSTEC dataset extracts CVSS base scores from vector strings (v2.0, v3.0, v4.0) and includes CVE cross-references when available.


### CWE/patch dataset

Generate a dataset associating Git fixes with Common Weakness Enumerations (CWEs) found in security advisories:

```bash
python vulntrain/datasets/cwe-guesser-dataset.py --sources cvelistv5,github,pysec,csaf_redhat --repo-id=CIRCL/vulnerability-cwe-patch
```

By default the script appends to the existing dataset on the Hub. Pass
`--from-scratch` to rebuild it entirely (required when the dataset schema
changes).


### CVE/ATT&CK techniques dataset

Generate a dataset mapping CVEs to MITRE ATT&CK techniques from the hand-curated
MITRE CTID mappings, with descriptions joined from `CIRCL/vulnerability-scores`:

```bash
vulntrain-dataset-attack-generation --push --repo-id=CIRCL/vulnerability-attack-techniques
```

See the [methodology documentation](attack-techniques-dataset.md) for the label
source analysis (including why the automatically derived CVE2CAPEC labels are
kept as a separate weak column rather than used as training targets), the
dataset schema, and known limitations.


## Model training

### Severity classification

Generate the model [CIRCL/vulnerability-severity-classification-roberta-base](https://huggingface.co/CIRCL/vulnerability-severity-classification-roberta-base):

```bash
vulntrain-train-severity-classification --base-model roberta-base --dataset-id CIRCL/vulnerability-scores --repo-id CIRCL/vulnerability-severity-classification-roberta-base
```

Generate the model [CIRCL/vulnerability-severity-classification-chinese-macbert-base](https://huggingface.co/CIRCL/vulnerability-severity-classification-chinese-macbert-base):

```bash
vulntrain-train-severity-cnvd-classification --base-model hfl/chinese-macbert-base --dataset-id CIRCL/Vulnerability-CNVD --repo-id CIRCL/vulnerability-severity-classification-chinese-macbert-base
```

The CNVD trainer uses a deduplicated train/test split to prevent data leakage and supports different loss strategies via `--class-weights` (`none`, `sqrt`, `balanced`, `focal`). Defaults to uniform loss. See the [improvements report](cnvd-severity-improvements.md) for details.

Generate a Russian severity classifier using FSTEC data and [ruRoberta-large](https://huggingface.co/ai-forever/ruRoberta-large):

```bash
vulntrain-train-severity-classification --base-model ai-forever/ruRoberta-large --dataset-id CIRCL/Vulnerability-FSTEC --repo-id CIRCL/vulnerability-severity-classification-russian-ruRoberta-large
```

### CWE classification

Predict CWE classifications from vulnerability descriptions and associated patches.
The recommended base model is [ModernBERT-base](https://huggingface.co/answerdotai/ModernBERT-base),
whose 8192-token context window can take the full patches into account:

```bash
vulntrain-train-cwe-classification --base-model answerdotai/ModernBERT-base --dataset-id CIRCL/vulnerability-cwe-patch --repo-id CIRCL/vulnerability-cwe-classification-modernbert-base --batch-size 8
```

Shorter-context models such as `roberta-base` also work (truncation adapts to
the model's maximum input length, overridable with `--max-length`). The loss
strategy for class imbalance can be selected with `--class-weights` (`none`,
`sqrt`, `balanced`, `focal`; defaults to `balanced`), and `--epochs`,
`--learning-rate` and `--batch-size` control the schedule. Reported metrics
include top-3/top-5 accuracy, since the model is used to suggest candidate
CWEs. See the [improvements report](cwe-classification-improvements.md) for
the reasoning behind these options.

The trainer maps each CWE of the dataset to an ancestor CWE via
`vulntrain/data/deep_child_to_ancestor.json`, built so that every training
label has an *Allowed* or *Allowed-with-Review* MITRE mapping usage: the model
can never suggest a Discouraged or Prohibited CWE.

This mapping is versioned and shipped with VulnTrain, so no extra step is
required before training. To optionally refresh it against the latest CWE
data from [Vulnerability-Lookup](https://vulnerability.circl.lu), run the
following commands before training and commit the regenerated files:

```bash
python tools/cwe/update_cwe_knowledge_base.py   # refresh the CWE knowledge base from the API
python tools/cwe/build_child_to_ancestor.py     # regenerate vulntrain/data/deep_child_to_ancestor.json
```

See `tools/cwe/README.md` for details.


### ATT&CK technique classification

Suggest MITRE ATT&CK (Enterprise) techniques from vulnerability descriptions.
This is a **multi-label** task (a CVE maps to an exploitation technique plus
one or more impacts), trained with a sigmoid head and binary cross-entropy on
the [CIRCL/vulnerability-attack-techniques](https://huggingface.co/datasets/CIRCL/vulnerability-attack-techniques)
dataset:

```bash
vulntrain-train-attack-classification --base-model roberta-base --dataset-id CIRCL/vulnerability-attack-techniques --repo-id CIRCL/vulnerability-attack-technique-classification-roberta-base
```

Sub-techniques are collapsed to their parent technique (`--keep-subtechniques`
to disable) and only techniques with at least `--min-examples` (default 5)
training examples are kept in the label vocabulary. Per-label BCE positive
weights counter class imbalance (`--class-weights none|sqrt|balanced`), and
`--epochs`, `--learning-rate`, `--batch-size` and `--max-length` control the
schedule as in the CWE trainer. Reported metrics include recall@3/recall@5,
since the model is used to suggest candidate techniques for analyst review.
See the [methodology documentation](attack-techniques-dataset.md) for the
dataset provenance and known limitations.


### Text generation

Train a GPT-2 model to generate vulnerability descriptions:

```bash
vulntrain-train-description-generation --base-model gpt2-xl --dataset-id CIRCL/vulnerability-scores --repo-id CIRCL/vulnerability-description-generation-gpt2-xl
```



## Validation

### Severity model comparison (CNVD)

Compare old and new CNVD severity models on a deduplicated test set:

```bash
python -m vulntrain.validators.severity_cnvd \
  --old-model CIRCL/vulnerability-severity-classification-chinese-macbert-base \
  --new-model CIRCL/vulnerability-severity-classification-chinese-macbert-base-test
```

### ATT&CK technique models

Evaluate ATT&CK technique suggestion on the test split of
[CIRCL/vulnerability-attack-techniques](https://huggingface.co/datasets/CIRCL/vulnerability-attack-techniques).
The zero-shot similarity baseline (SMET-style: rank techniques by cosine
similarity between the description embedding and the official ATT&CK
technique descriptions) and a fine-tuned classifier share the same protocol,
so their recall@k/MRR numbers are directly comparable — the trained model has
to beat the baseline to justify existing:

```bash
vulntrain-validate-attack-classification --method similarity
vulntrain-validate-attack-classification --method classifier --model CIRCL/vulnerability-attack-technique-classification-roberta-base
```

### Text generation

Send prompts to a model trained for vulnerability description generation:

```bash
vulntrain-validate-text-generation --prompt "A new vulnerability in OpenSSL allows attackers to" --model CIRCL/vulnerability-description-generation-gpt2-large
```

## Citation

Bonhomme, C., Dulaunoy, A. (2025). VLAI: A RoBERTa-Based Model for Automated Vulnerability Severity Classification (Version 1.4.0) [Computer software]. https://arxiv.org/abs/2507.03607

Cédric Bonhomme, Alexandre Dulaunoy, “VLAI: A RoBERTa-Based Model for Automated Vulnerability Severity Classification”, preprint for the 25V4C-TC: 2025 Vulnerability Forecasting Technical Colloquia, Darwin College, Cambridge, UK, September 25–26, 2025.  
https://arxiv.org/abs/2507.03607


## License

[VulnTrain](https://github.com/vulnerability-lookup/VulnTrain) is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)

~~~
Copyright (c) 2025-2026 Computer Incident Response Center Luxembourg (CIRCL)
Copyright (C) 2025-2026 Cédric Bonhomme - https://github.com/cedricbonhomme
Copyright (C) 2025 Léa Ulusan - https://github.com/3LS3-1F
~~~

