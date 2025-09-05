import subprocess

# List of base models to test
base_models = [
    "bert-base-uncased",
    "roberta-base",
    "distilbert-base-uncased",
    "microsoft/codebert-base",
    "microsoft/graphcodebert-base",
    "huggingface/CodeBERTa-small-v1",
]

dataset_id = "CIRCL/vulnerability-cwe-patch"
hf_repo_prefix = "CIRCL/vuln-patch-cwe-guesser-model"
save_dir_base = "results"

for model_name in base_models:
    print(f"\n==== Running training for: {model_name} ====")

    repo_id = f"{hf_repo_prefix}-{model_name.replace('/', '-')}"
    save_dir = f"{save_dir_base}/{model_name.replace('/', '-')}"

    subprocess.run(
        [
            "python",
            "vulntrain/trainers/cwe-guesser-commit-mess.py",
            "--base-model",
            model_name,
            "--dataset-id",
            dataset_id,
            "--repo-id",
            repo_id,
            "--model-save-dir",
            save_dir,
        ]
    )
