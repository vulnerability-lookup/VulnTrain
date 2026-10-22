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

A fine-tuned [{base_model}](https://huggingface.co/{base_model}) model for classifying French security bulletins from [CERT-FR](https://www.cert.ssi.gouv.fr/) into {num_classes} severity levels: {label_list}.

Trained on the [{dataset_id}](https://huggingface.co/datasets/{dataset_id}) dataset as part of the [VulnTrain](https://github.com/vulnerability-lookup/VulnTrain) project.

## Labels

CERT-FR bulletins carry no severity rating of their own. Each bulletin is labelled from the CVSS scores of the CVEs it references (`{score_field}`), mapped with the CVSS v3 thresholds (Low < 4.0 ≤ Medium < 7.0 ≤ High < 9.0 ≤ Critical); {cvss_v2_description}. {low_description} The model therefore estimates the severity of the most severe vulnerability described by a bulletin.

The input text is the bulletin title, its summary, and the list of risks identified by CERT-FR.

## Evaluation results

Evaluated on a **deduplicated test set** ({test_samples} samples) where no input text appears in both train and test splits, as many CERT-FR summaries follow the same template.

| Class    | Precision | Recall | F1-score | Support |
|----------|-----------|--------|----------|---------|
{class_table}

- **Overall accuracy**: {accuracy:.2%}
- **Macro F1**: {f1_macro:.4f}

For comparison, a TF-IDF + logistic regression baseline trained on the same split reaches an accuracy of {baseline_accuracy:.2%} and a macro F1 of {baseline_f1_macro:.4f}.

### Class distribution

The test set is imbalanced: {class_distribution}.

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

- **Low severity**: Low-severity bulletins are rare (about 1% of the dataset) and are not learned reliably.
- **High vs. Critical**: many bulletins score just below or just above 9.0 (8.8 and 9.8 are the most frequent scores), a difference the bulletin text rarely reflects.
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
