---
language:
- fr
license: cc-by-4.0
library_name: transformers
tags:
- text-classification
- vulnerability
- severity
- cybersecurity
- cert-fr
datasets:
- CIRCL/Vulnerability-CERT-FR
base_model: {base_model}
pipeline_tag: text-classification
---

# VLAI: Automated Vulnerability Severity Classification (French Text)

A fine-tuned [{base_model}](https://huggingface.co/{base_model}) model for classifying French security bulletins from [CERT-FR](https://www.cert.ssi.gouv.fr/) into four severity levels: **Low**, **Medium**, **High**, and **Critical**.

Trained on the [{dataset_id}](https://huggingface.co/datasets/{dataset_id}) dataset as part of the [VulnTrain](https://github.com/vulnerability-lookup/VulnTrain) project.

## Labels

CERT-FR bulletins carry no severity rating of their own. Each bulletin is labelled from the CVSS scores of the CVEs it references (`{score_field}`), mapped with the CVSS v3 thresholds (Low < 4.0 ≤ Medium < 7.0 ≤ High < 9.0 ≤ Critical); {cvss_v2_description}. The model therefore estimates the severity of the most severe vulnerability described by a bulletin.

The input text is the bulletin title, its summary, and the list of risks identified by CERT-FR.

## Evaluation results

Evaluated on a **deduplicated test set** ({test_samples} samples) where no input text appears in both train and test splits, as many CERT-FR summaries follow the same template.

| Class    | Precision | Recall | F1-score | Support |
|----------|-----------|--------|----------|---------|
| Low      | {Low_precision:.4f}      | {Low_recall:.4f} | {Low_f1:.4f}      | {Low_support}      |
| Medium   | {Medium_precision:.4f}   | {Medium_recall:.4f} | {Medium_f1:.4f}   | {Medium_support}   |
| High     | {High_precision:.4f}     | {High_recall:.4f} | {High_f1:.4f}     | {High_support}     |
| Critical | {Critical_precision:.4f} | {Critical_recall:.4f} | {Critical_f1:.4f} | {Critical_support} |

- **Overall accuracy**: {accuracy:.2%}
- **Macro F1**: {f1_macro:.4f}

### Class distribution

The dataset is imbalanced: Low ({Low_pct:.1f}%), Medium ({Medium_pct:.1f}%), High ({High_pct:.1f}%), Critical ({Critical_pct:.1f}%).

## Usage

```python
from transformers import pipeline

classifier = pipeline(
    "text-classification",
    model="{repo_id}"
)

text = """Multiples vulnérabilités dans PHP
De multiples vulnérabilités ont été découvertes dans PHP. Elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance.
Risques : Exécution de code arbitraire à distance."""
result = classifier(text)
print(result)
```

## Known limitations

- **Low severity**: Low-severity bulletins are rare (about 1–2% of the dataset), so this class is poorly learned and its metrics are computed on few samples.
- **Bulletin-level labels**: a bulletin covering several vulnerabilities is labelled with the score of its referenced CVEs, not with an assessment by CERT-FR. Bulletins referencing more than 10 CVEs are not part of the dataset.

## Training details

- **Base model**: [{base_model}](https://huggingface.co/{base_model})
- **Dataset**: [{dataset_id}](https://huggingface.co/datasets/{dataset_id})
- **Train/test split**: deduplicated on input text (no leakage), 80/20 split
- **Loss**: {loss_description}
- **Learning rate**: {learning_rate}
- **Batch size**: {batch_size}
- **Epochs**: {num_epochs}
- **Best model selection**: by macro F1

## References

- [Vulnerability-Lookup](https://vulnerability.circl.lu) — the vulnerability data source
- [VulnTrain](https://github.com/vulnerability-lookup/VulnTrain) — training pipeline
- [ML-Gateway](https://github.com/vulnerability-lookup/ML-Gateway) — inference API
- [VLAI paper](https://arxiv.org/abs/2507.03607) — Bonhomme, C., Dulaunoy, A. (2025)
- [CERT-FR](https://www.cert.ssi.gouv.fr/) — the source of the bulletins
