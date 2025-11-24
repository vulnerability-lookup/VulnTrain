# VulnTrain documentation

<!-- ```{contents} Table of Contents
:depth: 3
``` -->

## Presentation

VulnTrain provides a set of tools to generate diverse AI-ready datasets and train models using comprehensive vulnerability data from Vulnerability-Lookup.
It leverages over one million JSON records from multiple advisory sources to build high-quality, domain-specific models.


## Installation

```bash
git clone https://github.com/vulnerability-lookup/VulnTrain.git
cd VulnTrain/
poetry install
```

Three types of commands are available:

- **Dataset generation**: Create and prepare datasets.
- **Model training**: Train models using the prepared datasets.
- **Model validation**: Evaluate the performance of trained models.

For AMD Ryzen GPU:

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

Then ensure that the kvrocks database of Vulnerability-Lookup is running.


### Vulnerabililty severity scores

Example: Generate [CIRCL/vulnerability-scores](https://huggingface.co/datasets/CIRCL/vulnerability-scores) dataset

```bash
vulntrain-dataset-generation --sources cvelistv5,github,csaf_redhat,csaf_cisco,csaf_cisa,pysec --repo-id=CIRCL/vulnerability-scores
```

Example: Generate [CIRCL/Vulnerability/CNVD](https://huggingface.co/datasets/CIRCL/Vulnerability-CNVD) dataset

```bash
vulntrain-dataset-generation --sources cnvd --repo-id=CIRCL/Vulnerability-CNVD
```


### Associating Git Fixes with Common Weakness Enumerations (CWEs)

```bash
python vulntrain/datasets/cwe-guesser-dataset.py --sources cvelistv5,github,pysec,csaf_redhat --repo-id=CIRCL/vulnerability-cwe-patch
```



## Model training

### Training for severity classification

Generate the model [CIRCL/vulnerability-severity-classification-roberta-base](https://huggingface.co/CIRCL/vulnerability-severity-classification-roberta-base):

```bash
vulntrain-train-severity-classification --base-model roberta-base --dataset-id CIRCL/vulnerability-scores --repo-id CIRCL/vulnerability-severity-classification-roberta-base
```

Generate the model [CIRCL/vulnerability-severity-classification-chinese-macbert-base](https://huggingface.co/CIRCL/vulnerability-severity-classification-chinese-macbert-base):

```bash
vulntrain-train-severity-cnvd-classification --base-model hfl/chinese-macbert-base --dataset-id CIRCL/Vulnerability-CNVD --repo-id CIRCL/vulnerability-severity-classification-chinese-macbert-base
```

### Training for CWE classification

```bash
vulntrain-train-cwe-classification --base-model roberta-base --dataset-id CIRCL/vulnerability-cwe-patch --repo-id CIRCL/cwe-parent-vulnerability-classification-roberta-base 
```


### Training for text generation

For now we are using GPT-2 (AutoModelForCausalLM) or distilbert-base-uncased (AutoModelForMaskedLM).
The goal is to generate text.

```bash
$ vulntrain-train-description-generation --base-model gpt2 --dataset-id CIRCL/vulnerability --repo-id CIRCL/vulnerability-description-generation-gpt2
Using CUDA (Nvidia GPU).
[codecarbon WARNING @ 13:28:13] Multiple instances of codecarbon are allowed to run at the same time.
[codecarbon INFO @ 13:28:13] [setup] RAM Tracking...
[codecarbon INFO @ 13:28:13] [setup] CPU Tracking...
[codecarbon WARNING @ 13:28:13] No CPU tracking mode found. Falling back on CPU constant mode. 
 Linux OS detected: Please ensure RAPL files exist at \sys\class\powercap\intel-rapl to measure CPU

[codecarbon WARNING @ 13:28:14] We saw that you have a AMD EPYC 9124 16-Core Processor but we don't know it. Please contact us.
[codecarbon INFO @ 13:28:14] CPU Model on constant consumption mode: AMD EPYC 9124 16-Core Processor
[codecarbon INFO @ 13:28:14] [setup] GPU Tracking...
[codecarbon INFO @ 13:28:14] Tracking Nvidia GPU via pynvml
[codecarbon INFO @ 13:28:14] >>> Tracker's metadata:
[codecarbon INFO @ 13:28:14]   Platform system: Linux-6.8.0-48-generic-x86_64-with-glibc2.39
[codecarbon INFO @ 13:28:14]   Python version: 3.12.3
[codecarbon INFO @ 13:28:14]   CodeCarbon version: 2.8.3
[codecarbon INFO @ 13:28:14]   Available RAM : 251.586 GB
[codecarbon INFO @ 13:28:14]   CPU count: 64
[codecarbon INFO @ 13:28:14]   CPU model: AMD EPYC 9124 16-Core Processor
[codecarbon INFO @ 13:28:14]   GPU count: 2
[codecarbon INFO @ 13:28:14]   GPU model: 2 x NVIDIA L40S
[codecarbon INFO @ 13:28:18] Saving emissions data to file /home/cedric/VulnTrain/emissions.csv                                    | 1/2700 [00:07<5:45:36,  7.68s/it]
...
...
...
```



## Validation

It is possible to send prompts to a model trained for text generation (descriptions of vulnerabilities).

```bash
$ vulntrain-validate-text-generation --help
usage: vulntrain-validate-text-generation [-h] [--model MODEL] [--prompt PROMPT]

Validate a text generation model for vulnerabilities.

options:
  -h, --help       show this help message and exit
  --model MODEL    The model to use.
  --prompt PROMPT  The prompt for the generator.
```

Example:

```bash
$ vulntrain-validate-text-generation --prompt "A new vulnerability in OpenSSL allows attackers to" --model CIRCL/vulnerability-description-generation-gpt2-large
config.json: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 907/907 [00:00<00:00, 6.70MB/s]
model.safetensors: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 498M/498M [00:12<00:00, 41.3MB/s]
generation_config.json: 100%|██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 119/119 [00:00<00:00, 1.63MB/s]
tokenizer_config.json: 100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 556/556 [00:00<00:00, 4.01MB/s]
vocab.json: 100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 798k/798k [00:00<00:00, 3.25MB/s]
merges.txt: 100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 456k/456k [00:00<00:00, 5.58MB/s]
tokenizer.json: 100%|██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 3.56M/3.56M [00:00<00:00, 10.3MB/s]
special_tokens_map.json: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 470/470 [00:00<00:00, 3.51MB/s]
Device set to use cuda:0

[{'generated_text': 'A new vulnerability in OpenSSL allows attackers to bypass the TLS 1.2.1 server-side certificate validation by using a specially crafted (but not necessarily signed) client certificate to connect to a server. This issue affects: OpenSSL 3.0 versions prior to 3.0.4.1. OpenSSL 2.0 versions prior to 2.0.0.43. OpenSSL 1.1 versions prior to 1.1.0.27. OpenSSL 1.0 versions prior to 1.0.1.22. OpenSSL 0.9.6 versions prior to 0.9.6i.7. OpenSSL 0.8.7 versions prior to 0.8.7p14. Fixed in OpenSSL 3.0.4.1 (Affected 3.0.0,3.0.1,3.0.2). Fixed in OpenSSL 2.0.0.43 (Affected 2.0.0.43). Fixed in OpenSSL 1.1.0.27 (Affected 1.1.0.26). Fixed in OpenSSL 1.0.1.22 (Affected 1.0.1.21). Fixed in OpenSSL 0.9.6i.7 (Affected 0'}]
```

## Citation

Bonhomme, C., Dulaunoy, A. (2025). VLAI: A RoBERTa-Based Model for Automated Vulnerability Severity Classification (Version 1.4.0) [Computer software]. https://arxiv.org/abs/2507.03607

Cédric Bonhomme, Alexandre Dulaunoy, “VLAI: A RoBERTa-Based Model for Automated Vulnerability Severity Classification”, preprint for the 25V4C-TC: 2025 Vulnerability Forecasting Technical Colloquia, Darwin College, Cambridge, UK, September 25–26, 2025.  
https://arxiv.org/abs/2507.03607


## License

[VulnTrain](https://github.com/vulnerability-lookup/VulnTrain) is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)

~~~
Copyright (c) 2025 Computer Incident Response Center Luxembourg (CIRCL)
Copyright (C) 2025 Cédric Bonhomme - https://github.com/cedricbonhomme
Copyright (C) 2025 Léa Ulusan - https://github.com/3LS3-1F
~~~

