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
base_model: {base_model}
pipeline_tag: text-classification
---

# VLAI: Automated Vulnerability Severity Classification (Chinese Text)

A fine-tuned [{base_model}](https://huggingface.co/{base_model}) model for classifying Chinese vulnerability descriptions from the [China National Vulnerability Database (CNVD)](https://www.cnvd.org.cn/) into three severity levels: **Low**, **Medium**, and **High**.

Trained on the [{dataset_id}](https://huggingface.co/datasets/{dataset_id}) dataset as part of the [VulnTrain](https://github.com/vulnerability-lookup/VulnTrain) project.

## Evaluation results

Evaluated on a **deduplicated test set** ({test_samples} samples) where no description text appears in both train and test splits, preventing data leakage from CNVD's reuse of boilerplate descriptions across different vulnerability IDs.

| Class  | Precision | Recall | F1-score | Support |
|--------|-----------|--------|----------|---------|
| Low    | {Low_precision:.4f}    | {Low_recall:.4f} | {Low_f1:.4f}   | {Low_support}   |
| Medium | {Medium_precision:.4f} | {Medium_recall:.4f} | {Medium_f1:.4f} | {Medium_support} |
| High   | {High_precision:.4f}   | {High_recall:.4f} | {High_f1:.4f}   | {High_support}   |

- **Overall accuracy**: {accuracy:.2%}
- **Macro F1**: {f1_macro:.4f}

### Class distribution

The dataset is imbalanced: Low ({Low_pct:.1f}%), Medium ({Medium_pct:.1f}%), High ({High_pct:.1f}%).

## Usage

```python
from transformers import pipeline

classifier = pipeline(
    "text-classification",
    model="{repo_id}"
)

description = "TOTOLINK A3600R存在缓冲区溢出漏洞，攻击者可利用该漏洞在系统上执行任意代码或者导致拒绝服务。"
result = classifier(description)
print(result)
```

## Known limitations

- **Low severity recall**: the Low class has the lowest recall. Approximately 60% of Low-severity entries are misclassified, mostly as Medium. This reflects the vocabulary overlap between Low and Medium descriptions in CNVD data. Class-weighted loss and focal loss were tested but all degraded Medium recall disproportionately without a net benefit.

- **Keyword dependency**: the model biases toward a vulnerability type's typical severity. For example, buffer overflow descriptions are predicted as High regardless of the actual assigned severity. On entries where the actual severity deviates from the type's typical severity, accuracy drops from ~89% to ~55%.

- **Negation blindness**: the model does not understand negation. Descriptions like "does NOT allow remote code execution" can still produce high-confidence High severity predictions.

- **CVE overlap**: 81% of CNVD entries have a corresponding CVE. The model primarily adds value for the ~19% of CNVD-only entries (concentrated in Chinese domestic software) where no CVE severity assessment exists.

These limitations were identified through independent analysis in [VulnTrain#19](https://github.com/vulnerability-lookup/VulnTrain/issues/19).

## Training details

- **Base model**: [{base_model}](https://huggingface.co/{base_model})
- **Dataset**: [{dataset_id}](https://huggingface.co/datasets/{dataset_id})
- **Train/test split**: deduplicated on description text (no leakage), 80/20 split
- **Loss**: {loss_description}
- **Learning rate**: {learning_rate}
- **Batch size**: {batch_size}
- **Epochs**: {num_epochs}
- **Best model selection**: by accuracy

## References

- [Vulnerability-Lookup](https://vulnerability.circl.lu) - the vulnerability data source
- [VulnTrain](https://github.com/vulnerability-lookup/VulnTrain) - training pipeline
- [ML-Gateway](https://github.com/vulnerability-lookup/ML-Gateway) - inference API
