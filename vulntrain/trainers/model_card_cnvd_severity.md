---
language:
- zh
license: apache-2.0
library_name: transformers
tags:
- text-classification
- vulnerability
- severity
- cybersecurity
- cnvd
datasets:
- CIRCL/Vulnerability-CNVD
base_model: hfl/chinese-macbert-base
pipeline_tag: text-classification
---

# VLAI: Automated Vulnerability Severity Classification (Chinese Text)

A fine-tuned [hfl/chinese-macbert-base](https://huggingface.co/hfl/chinese-macbert-base) model for classifying Chinese vulnerability descriptions from the [China National Vulnerability Database (CNVD)](https://www.cnvd.org.cn/) into three severity levels: **Low**, **Medium**, and **High**.

Trained on the [CIRCL/Vulnerability-CNVD](https://huggingface.co/datasets/CIRCL/Vulnerability-CNVD) dataset as part of the [VulnTrain](https://github.com/vulnerability-lookup/VulnTrain) project.

## Evaluation results

Evaluated on a **deduplicated test set** (25,845 samples) where no description text appears in both train and test splits, preventing data leakage from CNVD's reuse of boilerplate descriptions across different vulnerability IDs.

| Class  | Precision | Recall | F1-score | Support |
|--------|-----------|--------|----------|---------|
| Low    | 0.5968    | 0.4099 | 0.4860   | 2,293   |
| Medium | 0.7867    | 0.8165 | 0.8013   | 14,351  |
| High   | 0.7662    | 0.7809 | 0.7735   | 9,201   |

- **Overall accuracy**: 76.8%
- **Macro F1**: 0.6870
- **Weighted F1**: 0.7634

### Class distribution

The dataset is imbalanced: Low (8.9%), Medium (55.5%), High (35.6%).

## Usage

```python
from transformers import pipeline

classifier = pipeline(
    "text-classification",
    model="CIRCL/vulnerability-severity-classification-chinese-macbert-base"
)

description = "TOTOLINK A3600R存在缓冲区溢出漏洞，攻击者可利用该漏洞在系统上执行任意代码或者导致拒绝服务。"
result = classifier(description)
print(result)
# [{'label': 'High', 'score': 0.98}]
```

## Known limitations

- **Low severity recall is ~41%**: approximately 60% of Low-severity entries are misclassified, mostly as Medium. This reflects the vocabulary overlap between Low and Medium descriptions in CNVD data. Class-weighted loss and focal loss were tested but all degraded Medium recall disproportionately without a net benefit.

- **Keyword dependency**: the model biases toward a vulnerability type's typical severity. For example, buffer overflow descriptions are predicted as High regardless of the actual assigned severity. On entries where the actual severity deviates from the type's typical severity, accuracy drops from ~89% to ~55%.

- **Negation blindness**: the model does not understand negation. Descriptions like "does NOT allow remote code execution" can still produce high-confidence High severity predictions.

- **CVE overlap**: 81% of CNVD entries have a corresponding CVE. The model primarily adds value for the ~19% of CNVD-only entries (concentrated in Chinese domestic software) where no CVE severity assessment exists.

These limitations were identified through independent analysis in [VulnTrain#19](https://github.com/vulnerability-lookup/VulnTrain/issues/19).

## Training details

- **Base model**: [hfl/chinese-macbert-base](https://huggingface.co/hfl/chinese-macbert-base)
- **Dataset**: [CIRCL/Vulnerability-CNVD](https://huggingface.co/datasets/CIRCL/Vulnerability-CNVD)
- **Train/test split**: deduplicated on description text (no leakage), 80/20 split
- **Loss**: uniform cross-entropy (no class weighting)
- **Learning rate**: 3e-05
- **Batch size**: 16
- **Epochs**: 5
- **Best model selection**: by accuracy

## References

- [Vulnerability-Lookup](https://vulnerability.circl.lu) - the vulnerability data source
- [VulnTrain](https://github.com/vulnerability-lookup/VulnTrain) - training pipeline
- [ML-Gateway](https://github.com/vulnerability-lookup/ML-Gateway) - inference API
