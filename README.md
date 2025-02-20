# VulnTrain

Generate datasets amd models based on vulnerabilities descriptions from Vulnerability-Lookup.

Uses data from the ``vulnerability-lookup:meta`` container such as vulnrichment and FKIE.


## Datasets

Various datasets generated are available on HuggingFace:

https://huggingface.co/datasets/circl/vulnerability-dataset


## Usage

### Generate datasets

Authenticate to HuggingFace:

```bash
huggingface-cli login
```

Install VulnTrain:

```bash
$ pipx install VulnTrain
```

Then ensures that the kvrocks database of Vulnerability-Lookup is running.


Creation of datasets:

```bash
$ vulntrain-create-dataset --nb-rows 10000 --upload --repo-id CIRCL/vulnerability-dataset-10k
Generating train split: 9999 examples [00:00, 177710.74 examples/s]
DatasetDict({
    train: Dataset({
        features: ['id', 'title', 'description', 'cpes'],
        num_rows: 8999
    })
    test: Dataset({
        features: ['id', 'title', 'description', 'cpes'],
        num_rows: 1000
    })
})
Creating parquet from Arrow format: 100%|██████████████████████████████████████████████████████████████████████████████| 9/9 [00:00<00:00, 49.66ba/s]
Uploading the dataset shards: 100%|████████████████████████████████████████████████████████████████████████████████████| 1/1 [00:02<00:00,  2.03s/it]
Creating parquet from Arrow format: 100%|██████████████████████████████████████████████████████████████████████████████| 1/1 [00:00<00:00, 63.36ba/s]
Uploading the dataset shards: 100%|████████████████████████████████████████████████████████████████████████████████████| 1/1 [00:01<00:00,  1.19s/it]
README.md: 100%|████████████████████████████████████████████████████████████████████████████████████████████████████| 503/503 [00:00<00:00, 2.34MB/s]
```


### Train

#### Training for text generation

For now we are using distilbert-base-uncased (AutoModelForMaskedLM) or gpt2 (AutoModelForCausalLM).
The goal is to generate text.

```bash
$ vulntrain-train-dataset 
Using CPU.
[codecarbon WARNING @ 07:45:34] Multiple instances of codecarbon are allowed to run at the same time.
[codecarbon INFO @ 07:45:34] [setup] RAM Tracking...
[codecarbon INFO @ 07:45:34] [setup] CPU Tracking...
[codecarbon WARNING @ 07:45:34] No CPU tracking mode found. Falling back on CPU constant mode. 
 Linux OS detected: Please ensure RAPL files exist at \sys\class\powercap\intel-rapl to measure CPU

[codecarbon WARNING @ 07:45:36] We saw that you have a 13th Gen Intel(R) Core(TM) i7-1365U but we don't know it. Please contact us.
[codecarbon INFO @ 07:45:36] CPU Model on constant consumption mode: 13th Gen Intel(R) Core(TM) i7-1365U
[codecarbon INFO @ 07:45:36] [setup] GPU Tracking...
[codecarbon INFO @ 07:45:36] No GPU found.
[codecarbon INFO @ 07:45:36] >>> Tracker's metadata:
[codecarbon INFO @ 07:45:36]   Platform system: Linux-6.1.0-31-amd64-x86_64-with-glibc2.36
[codecarbon INFO @ 07:45:36]   Python version: 3.13.0
[codecarbon INFO @ 07:45:36]   CodeCarbon version: 2.8.3
[codecarbon INFO @ 07:45:36]   Available RAM : 30.937 GB
[codecarbon INFO @ 07:45:36]   CPU count: 12
[codecarbon INFO @ 07:45:36]   CPU model: 13th Gen Intel(R) Core(TM) i7-1365U
[codecarbon INFO @ 07:45:36]   GPU count: None
[codecarbon INFO @ 07:45:36]   GPU model: None
[codecarbon INFO @ 07:45:39] Saving emissions data to file /home/cedric/git/VulnTrain/emissions.csv
Base model distilbert-base-uncased
README.md: 100%|████████████████████████████████████████████████████████████████████████████████████████████████████| 503/503 [00:00<00:00, 5.96MB/s]
train-00000-of-00001.parquet: 100%|█████████████████████████████████████████████████████████████████████████████| 1.48M/1.48M [00:00<00:00, 6.92MB/s]
test-00000-of-00001.parquet: 100%|█████████████████████████████████████████████████████████████████████████████████| 170k/170k [00:00<00:00, 488kB/s]
Generating train split: 100%|█████████████████████████████████████████████████████████████████████████| 8999/8999 [00:00<00:00, 277013.99 examples/s]
Generating test split: 100%|██████████████████████████████████████████████████████████████████████████| 1000/1000 [00:00<00:00, 205250.99 examples/s]
Map: 100%|██████████████████████████████████████████████████████████████████████████████████████████████| 8999/8999 [00:01<00:00, 8233.47 examples/s]
[codecarbon INFO @ 07:45:47] [setup] RAM Tracking...
[codecarbon INFO @ 07:45:47] [setup] CPU Tracking...
[codecarbon WARNING @ 07:45:47] No CPU tracking mode found. Falling back on CPU constant mode. 
 Linux OS detected: Please ensure RAPL files exist at \sys\class\powercap\intel-rapl to measure CPU

[codecarbon WARNING @ 07:45:48] We saw that you have a 13th Gen Intel(R) Core(TM) i7-1365U but we don't know it. Please contact us.
[codecarbon INFO @ 07:45:48] CPU Model on constant consumption mode: 13th Gen Intel(R) Core(TM) i7-1365U
[codecarbon INFO @ 07:45:48] [setup] GPU Tracking...
[codecarbon INFO @ 07:45:48] No GPU found.
[codecarbon INFO @ 07:45:48] >>> Tracker's metadata:
[codecarbon INFO @ 07:45:48]   Platform system: Linux-6.1.0-31-amd64-x86_64-with-glibc2.36
[codecarbon INFO @ 07:45:48]   Python version: 3.13.0
[codecarbon INFO @ 07:45:48]   CodeCarbon version: 2.8.3
[codecarbon INFO @ 07:45:48]   Available RAM : 30.937 GB
[codecarbon INFO @ 07:45:48]   CPU count: 12
[codecarbon INFO @ 07:45:48]   CPU model: 13th Gen Intel(R) Core(TM) i7-1365U
[codecarbon INFO @ 07:45:48]   GPU count: None
[codecarbon INFO @ 07:45:48]   GPU model: None
[codecarbon INFO @ 07:45:51] Saving emissions data to file /home/cedric/git/VulnTrain/vulnerability/emissions.csv
  0%|                                                                                                                       | 0/2700 [00:00<?, ?it/s][codecarbon INFO @ 07:45:54] Energy consumed for RAM : 0.000048 kWh. RAM Power : 11.601505279541016 W
[codecarbon INFO @ 07:45:54] Energy consumed for all CPUs : 0.000177 kWh. Total CPU Power : 42.5 W
[codecarbon INFO @ 07:45:54] 0.000225 kWh of electricity used since the beginning.
  0%|                                                                                                             | 1/2700 [00:07<5:45:36,  7.68s/it]
```


#### Training for classification

tf-idf on the vulnerability descriptions.



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



## License

[VulnTrain](https://github.com/vulnerability-lookup/VulnTrain) is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)

~~~
Copyright (c) 2025 Computer Incident Response Center Luxembourg (CIRCL)
Copyright (C) 2025 Cédric Bonhomme - https://github.com/cedricbonhomme
~~~

