---
title: AI datasets and VLAI models
description: Machine learning datasets and models
toc: true
---

## Introduction

At CIRCL (Computer Incident Response Center Luxembourg), we often face the challenge of evaluating vulnerabilities with incomplete data—sometimes just a textual description.

To tackle this, we developed an NLP-based model using data from our Vulnerability-Lookup platform. The entire solution is now publicly available, including its integration into our free online service and open-source codebase. With this model, you can generate a VLAI vulnerability severity score even when no official score exists, purely from the description. The model was presented in the paper [VLAI: A RoBERTa-Based Model for Automated Vulnerability Severity Classification](https://huggingface.co/papers/2507.03607) ([arXiv](https://arxiv.org/abs/2507.03607)).

What mattered most to us was mastering the full pipeline—from data collection and vulnerability correlation to AI-ready dataset generation, in-house model training, and seamless integration with Vulnerability-Lookup through a dedicated bridge.

We’ll continue to explore new models—always keeping in mind that AI is a tool, not a solution on its own!

Below, we outline the full process behind the VLAI Severity model—a framework that can be adapted to many other use cases.


## Datasets

We provide several datasets focused on software vulnerabilities. A key resource among them is dedicated to vulnerability scoring,
featuring structured CPE data, CVSS scores (across multiple versions), and rich textual descriptions.

### Vulnerabilities with CVSS scores

This dataset aggregates vulnerabilities from multiple sources, including:

- cvelistv5
- github
- csaf_redhat
- csaf_cisco
- csaf_cisa
- pysec

<iframe
  src="https://huggingface.co/datasets/CIRCL/vulnerability-scores/embed/viewer/default/train"
  frameborder="0"
  width="100%"
  height="560px"
></iframe>

This dataset is updated daily.

**Sources of the data:**

- [CVE Program](https://vulnerability.circl.lu/recent#cvelistv5) (enriched with data from vulnrichment and Fraunhofer FKIE)
- [GitHub Security Advisories](https://vulnerability.circl.lu/recent#github)
- [PySec advisories](https://vulnerability.circl.lu/recent#pysec)
- [CSAF Red Hat](https://vulnerability.circl.lu/recent#csaf_redhat)
- [CSAF Cisco](https://vulnerability.circl.lu/recent#csaf_cisco)

The licenses for each security advisory feed are listed here:  
<https://vulnerability.circl.lu/about#sources>

This represents more than 600,000 advisories available via the interface of Vulnerability-Lookup.


**Get started with the dataset:**

```python
import json
from datasets import load_dataset

dataset = load_dataset("CIRCL/vulnerability-scores")

vulnerabilities = ["CVE-2012-2339", "RHSA-2023:5964", "GHSA-7chm-34j8-4f22", "PYSEC-2024-225"]

filtered_entries = dataset.filter(lambda elem: elem["id"] in vulnerabilities)

for entry in filtered_entries["train"]:
    print(json.dumps(entry, indent=4))
```

For each vulnerability, you will find all assigned severity scores and associated CPEs.


### CNVD vulnerabilities

A separate dataset focuses on CNVD (China National Vulnerability Database) vulnerabilities, with descriptions in Chinese.

<iframe
  src="https://huggingface.co/datasets/CIRCL/Vulnerability-CNVD/embed/viewer/default/train"
  frameborder="0"
  width="100%"
  height="560px"
></iframe>

The dataset includes a `cve_id` field cross-referencing CVE equivalents (~81% of entries). The ~19% of CNVD-only entries are concentrated in Chinese domestic software. See the [dataset card](https://huggingface.co/datasets/CIRCL/Vulnerability-CNVD) for details on severity distribution, CVE overlap, and the post-2021 coverage decline following China's RMSV regulations.


### FSTEC vulnerabilities

A dataset of vulnerabilities from the Russian Federal Service for Technical and Export Control (FSTEC/BDU), with descriptions in Russian.

<iframe
  src="https://huggingface.co/datasets/CIRCL/Vulnerability-FSTEC/embed/viewer/default/train"
  frameborder="0"
  width="100%"
  height="560px"
></iframe>

CVSS base scores are parsed from vector strings (v2.0, v3.0, v4.0). CVE cross-references are included when available.


## Models

### How We Build Our VLAI Models

With the various vulnerability feeders of Vulnerability-Lookup (for the CVE Program, NVD, Fraunhofer FKIE, GHSA, PySec, CSAF sources, Japan Vulnerability Database, etc.) we’ve collected over a million JSON records.
This allows us to generate the dataset previously presented for training and building models.

![Model Generation](/images/user-manual/ai/models-generation.png)

As shown in the diagram, the AI dataset is generated (in step 2) by a dedicated project: [VulnTrain](https://github.com/vulnerability-lookup/VulnTrain).
This software is easy to install and usable via the command line.
It provides three main capabilities:

- **Dataset generation** – Create and prepare datasets from multiple sources (CVE, GitHub, CSAF, PySec, CNVD, FSTEC).
- **Model training** – Train models using the prepared datasets.
  - Train a model to **classify** vulnerabilities by severity (English, Chinese, Russian).
  - Train a model to **classify CWEs** from vulnerability descriptions and patches.
  - Train a model for **text generation** to assist in writing vulnerability descriptions.
- **Model validation** – Assess and compare the performance of trained models.

{{< callout type="info" >}}
  During our explorations, we found we could update a BERT-based text classification model daily using a dataset of approximately 600k rows from Vulnerability-Lookup. With sufficient GPU power, training takes only a few hours.
{{< /callout >}}

Models are generated using our own GPUs and our [open-source trainers](https://github.com/vulnerability-lookup/VulnTrain). Like the datasets, model updates are performed regularly.


### Text classification model

#### `vulnerability-severity-classification-roberta-base`

This model is a fine-tuned version of `RoBERTa base` trained on the [CIRCL/vulnerability-scores](https://huggingface.co/datasets/CIRCL/vulnerability-scores) dataset.

Training with two NVIDIA L40S GPUs takes about 6 hours.

{{< callout type="info" >}}
  We are getting point estimates from this model: the **predicted class** and its associated **probability** from the softmax layer.
{{< /callout >}}

Try it with Python:

```python
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import torch

labels = ["low", "medium", "high", "critical"]

model_name = "CIRCL/vulnerability-severity-classification-roberta-base"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name)
model.eval()

test_description = "langchain_experimental 0.0.14 allows an attacker to bypass the CVE-2023-36258 fix and execute arbitrary code via the PALChain in the python exec method."
inputs = tokenizer(test_description, return_tensors="pt", truncation=True, padding=True)

# Run inference
with torch.no_grad():
    outputs = model(**inputs)
    predictions = torch.nn.functional.softmax(outputs.logits, dim=-1)

# Print results
print("Predictions:", predictions)
predicted_class = torch.argmax(predictions, dim=-1).item()
print("Predicted severity:", labels[predicted_class])
```

Example output:

```
Predictions: tensor([[2.5910e-04, 2.1585e-03, 1.3680e-02, 9.8390e-01]])
Predicted severity: critical
```


#### `vulnerability-severity-classification-chinese-macbert-base`

This model is a fine-tuned version of `hfl/chinese-macbert-base` trained on the [CIRCL/Vulnerability-CNVD](https://huggingface.co/datasets/CIRCL/Vulnerability-CNVD) dataset.
It classifies severity of vulnerabilities based on Chinese descriptions into three levels: 低 (Low), 中 (Medium), and 高 (High).

The model achieves 76.8% accuracy on a deduplicated test set. Known limitations include low recall on the Low severity class (~41%) and keyword dependency. See the [model card](https://huggingface.co/CIRCL/vulnerability-severity-classification-chinese-macbert-base) and [improvements report](https://github.com/vulnerability-lookup/VulnTrain/blob/main/docs/cnvd-severity-improvements.md) for details.


#### `vulnerability-severity-classification-russian-ruRoberta-large`

This model is a fine-tuned version of [ai-forever/ruRoberta-large](https://huggingface.co/ai-forever/ruRoberta-large) trained on the [CIRCL/Vulnerability-FSTEC](https://huggingface.co/datasets/CIRCL/Vulnerability-FSTEC) dataset.
It classifies severity of vulnerabilities based on Russian descriptions from the FSTEC/BDU database.

It uses four labels: Low, Medium, High, and Critical (derived from CVSS scores).


## Putting Our Models to Work in Vulnerability-Lookup

![ML-Gateway](/images/user-manual/ai/ml-gateway.png)

[ML-Gateway](https://github.com/vulnerability-lookup/ML-Gateway) is a FastAPI-based local server that loads pre-trained NLP models at startup and exposes them via a RESTful API for inference.

Models are loaded **locally** via ML-Gateway to ensure minimal latency. All inference and processing are performed on our servers—no data is sent to Hugging Face.
We use the Hugging Face platform to share our datasets and models publicly, reinforcing our commitment to open collaboration.

Think of it as a lightweight model-serving layer that allows us to integrate multiple AI models without adding complexity to Vulnerability-Lookup.

Each model is accessible via dedicated HTTP endpoints. OpenAPI documentation is automatically generated and describes all available endpoints, input formats, and example responses—making integration straightforward. The ``/vlai/severity-classification`` API endpoint of Vulnerability-Lookup is relying on the API of ML-Gateway. Example:

```bash
$ curl -X 'POST' \
  'https://vulnerability.circl.lu/api/vlai/severity-classification' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "description": "An authentication bypass in the API component of Ivanti Endpoint Manager Mobile 12.5.0.0 and prior allows attackers to access protected resources without proper credentials via the API."
}'
{"severity": "High", "confidence": 0.6008}
```

The Vulnerability-Lookup backend simply forwards the request to the corresponding ML-Gateway endpoint and returns the result to the client. In our case the gateway is not directly accessible from the Web.

Ultimately, our goal is to enhance vulnerability data descriptions using a growing suite of NLP models, directly supporting Vulnerability-Lookup and related services.
