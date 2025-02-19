# VulnTrain

Generate datasets amd models based on vulnerabilities descriptions from Vulnerability-Lookup.

Uses data from the ``vulnerability-lookup:meta`` container such as vulnrichment and FKIE.


## Usage

### Generate datasets

Authenticate to HuggingFace:

```bash
huggingface-cli login
```

Creation of datasets:

```bash
$ pipx install VulnTrain

$ vulntrain-create-dataset 
DatasetDict({
    train: Dataset({
        features: ['id', 'title', 'description'],
        num_rows: 4
    })
    test: Dataset({
        features: ['id', 'title', 'description'],
        num_rows: 1
    })
})
Creating parquet from Arrow format: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1/1 [00:00<00:00, 1317.72ba/s]
Uploading the dataset shards: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1/1 [00:00<00:00,  1.16it/s]
Creating parquet from Arrow format: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1/1 [00:00<00:00, 2233.39ba/s]
Uploading the dataset shards: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1/1 [00:00<00:00,  1.39it/s]
README.md: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 428/428 [00:00<00:00, 1.70MB/s]
```


Train:

```bash
$ vulntrain-train-dataset 
```