# VulnTrain

[![Latest release](https://img.shields.io/github/release/vulnerability-lookup/VulnTrain.svg?style=flat-square)](https://github.com/vulnerability-lookup/VulnTrain/releases/latest)
[![License](https://img.shields.io/github/license/vulnerability-lookup/VulnTrain.svg?style=flat-square)](https://www.gnu.org/licenses/gpl-3.0.html)
[![PyPi version](https://img.shields.io/pypi/v/VulnTrain.svg?style=flat-square)](https://pypi.org/project/VulnTrain)


A tool for generating diverse datasets and models using vulnerability data from
[Vulnerability-Lookup](https://github.com/vulnerability-lookup/vulnerability-lookup).

It leverages all vulnerability advisory sources supported by Vulnerability-Lookup to train models, utilizing over one million JSON records.  
Additionally, data from the ``vulnerability-lookup:meta`` container, including enrichment sources such as vulnrichment and Fraunhofer FKIE, is incorporated to enhance model quality.

Check out the datasets and models on Hugging Face: 

[![Model on HF](https://huggingface.co/datasets/huggingface/badges/resolve/main/model-on-hf-xl-dark.svg)](https://huggingface.co/CIRCL)

For more information about the use of AI in Vulnerability-Lookup, please refer to the
[user manual](https://www.vulnerability-lookup.org/user-manual/ai/).


## Usage

Install VulnTrain:

```bash
$ pipx install VulnTrain
```

Three types of commands are available:

- **Dataset generation**: Create and prepare datasets.
- **Model training**: Train models using the prepared datasets.
  - Train a model for **text generation** to assist in writing vulnerability descriptions [![Model on HF](https://huggingface.co/datasets/huggingface/badges/resolve/main/model-on-hf-sm-dark.svg)](https://huggingface.co/CIRCL/vulnerability-description-generation-gpt2#how-to-get-started-with-the-model)
  - Train a model to **classify** vulnerabilities by severity. [![Model on HF](https://huggingface.co/datasets/huggingface/badges/resolve/main/model-on-hf-sm-dark.svg)](https://huggingface.co/CIRCL/vulnerability-severity-classification-distilbert-base-uncased)
- **Model validation**: Assess the performance of trained models.

### Dataset generation

Make sure you have HuggingFace installed, if you don't, here is the command line to install it :

```bash
pip install huggingface_hub
```

Authenticate to HuggingFace:

```bash
huggingface-cli login
```

Then ensure that the kvrocks database of Vulnerability-Lookup is running.


Creation of datasets:

```bash
$ vulntrain-dataset-generation --sources cvelistv5 --repo-id CIRCL/vulnerability-dataset-10k --nb-rows 10000
Generating train split: 9999 examples [00:00, 177710.74 examples/s]
DatasetDict({
    train: Dataset({
        features: ['id', 'title', 'description', 'cpes', 'cvss_v4_0', 'cvss_v3_1', 'cvss_v3_0', 'cvss_v2_0'],
        num_rows: 8999
    })
    test: Dataset({
        features: ['id', 'title', 'description', 'cpes', 'cvss_v4_0', 'cvss_v3_1', 'cvss_v3_0', 'cvss_v2_0'],
        num_rows: 1000
    })
})
Creating parquet from Arrow format: 100%|██████████████████████████████████████████████████████████████████████████████| 9/9 [00:00<00:00, 49.66ba/s]
Uploading the dataset shards: 100%|████████████████████████████████████████████████████████████████████████████████████| 1/1 [00:02<00:00,  2.03s/it]
Creating parquet from Arrow format: 100%|██████████████████████████████████████████████████████████████████████████████| 1/1 [00:00<00:00, 63.36ba/s]
Uploading the dataset shards: 100%|████████████████████████████████████████████████████████████████████████████████████| 1/1 [00:01<00:00,  1.19s/it]
README.md: 100%|████████████████████████████████████████████████████████████████████████████████████████████████████| 503/503 [00:00<00:00, 2.34MB/s]
```

In this example, the source consists of vulnerability advisories available in the Kvrocks database of Vulnerability-Lookup.
The script will automatically connect to the database using the Valkey client, generate two datasets (containing up to 10,000 rows), and upload the results to Hugging Face.

It is possible to add the GitHub Advisory Database (GHSA) as a source.


### Model training

#### Training for text generation

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


#### Training for classification

```bash
$ vulntrain-train-severity-classification --help
usage: vulntrain-train-severity-classification [-h] [--base-model {distilbert-base-uncased,roberta-base}] [--dataset-id DATASET_ID] --repo-id REPO_ID [--model-save-dir MODEL_SAVE_DIR]

Train a vulnerability classification model with a mapping on the severity.

options:
  -h, --help            show this help message and exit
  --base-model {distilbert-base-uncased,roberta-base}
                        Base model to use.
  --dataset-id DATASET_ID
                        Path of the dataset. Local dataset or repository on the HF hub.
  --repo-id REPO_ID     The name of the repository you want to push your object to. It should contain your organization name when pushing to a given organization.
  --model-save-dir MODEL_SAVE_DIR
                        The path to a directory where the tokenizer and the model will be saved.


$ vulntrain-train-severity-classification --base-model roberta-base --dataset-id CIRCL/vulnerability-scores --repo-id CIRCL/vulnerability-severity-classification-roberta-base
...
...
...
```


### Validation

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
$ vulntrain-validate-text-generation --prompt "A new vulnerability in OpenSSL allows attackers to" --model CIRCL/vulnerability
config.json: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 907/907 [00:00<00:00, 6.70MB/s]
model.safetensors: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 498M/498M [00:12<00:00, 41.3MB/s]
generation_config.json: 100%|██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 119/119 [00:00<00:00, 1.63MB/s]
tokenizer_config.json: 100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 556/556 [00:00<00:00, 4.01MB/s]
vocab.json: 100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 798k/798k [00:00<00:00, 3.25MB/s]
merges.txt: 100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 456k/456k [00:00<00:00, 5.58MB/s]
tokenizer.json: 100%|██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 3.56M/3.56M [00:00<00:00, 10.3MB/s]
special_tokens_map.json: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 470/470 [00:00<00:00, 3.51MB/s]
Device set to use cuda:0
Truncation was not explicitly activated but `max_length` is provided a specific value, please use `truncation=True` to explicitly truncate examples to max length. Defaulting to 'longest_first' truncation strategy. If you encode pairs of sequences (GLUE-style) with the tokenizer you can select this strategy more precisely by providing a specific strategy to `truncation`.

[{'generated_text': 'A new vulnerability in OpenSSL allows attackers to cause a Denial of Service (DoS) when receiving a specially crafted SIP message.\n\n\nThis issue affects: OpenSSL versions prior to 1.2.1\n\n\n\n *  OpenSSL 1.2.1 prior to 1.2.1-HF1, which fixes this issue.\n\n *  OpenSSL version 1.2.1 prior to 1.2.1-HF1 and OpenSSL 1.2.2 prior'}]
```



## License

[VulnTrain](https://github.com/vulnerability-lookup/VulnTrain) is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)

~~~
Copyright (c) 2025 Computer Incident Response Center Luxembourg (CIRCL)
Copyright (C) 2025 Cédric Bonhomme - https://github.com/cedricbonhomme
~~~

