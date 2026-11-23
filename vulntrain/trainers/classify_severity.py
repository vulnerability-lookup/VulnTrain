import argparse
import logging
import math
import shutil
from collections import Counter
from importlib import metadata
from pathlib import Path
from typing import Any

import evaluate
import numpy as np
from codecarbon import EmissionsTracker
from datasets import load_dataset
from sklearn.metrics import classification_report, f1_score
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    Trainer,
    TrainingArguments,
)

from vulntrain.utils import (
    clamp_tokenizer_max_length,
    ml_bom_metrics,
    push_emissions_report,
    read_emissions_report,
    resolve_dataset_revision,
    write_ml_bom,
)

"""
Automatically classify new vulnerabilities based on their descriptions,
even if they don't have CVSS scores.

Currently tested with distilbert-base-uncased and roberta-base.
"""

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define severity label mapping
SEVERITY_MAPPING = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


ID2LABEL = {v: k for k, v in SEVERITY_MAPPING.items()}

# Model card templates, by base model and dataset. A run with another pair
# keeps the card that the Trainer generates.
CARDS_DIR = Path(__file__).parent.parent / "cards"
CARD_TEMPLATES = {
    (
        "roberta-base",
        "CIRCL/vulnerability-scores",
    ): "model_card_vulnerability_scores_severity.md",
}


def compute_metrics(eval_pred):
    """Compute accuracy and per-class precision/recall/F1."""
    accuracy = evaluate.load("accuracy")
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=-1)

    acc = accuracy.compute(predictions=predictions, references=labels)
    macro_f1 = f1_score(labels, predictions, average="macro", zero_division=0)

    report = classification_report(
        labels,
        predictions,
        labels=list(range(len(SEVERITY_MAPPING))),
        target_names=[ID2LABEL[i] for i in range(len(SEVERITY_MAPPING))],
        output_dict=True,
        zero_division=0,
    )

    metrics = {**acc, "f1_macro": macro_f1}
    for label_name in SEVERITY_MAPPING:
        if label_name in report:
            metrics[f"{label_name}_precision"] = report[label_name]["precision"]
            metrics[f"{label_name}_recall"] = report[label_name]["recall"]
            metrics[f"{label_name}_f1"] = report[label_name]["f1-score"]

    return metrics


# Define severity mapping function
def map_cvss_to_severity(example, score_strategy="first"):
    """
    Map a CVSS score to a severity label and add it to the example.

    Parameters
    ----------
    example : dict
        A dictionary containing CVSS scores. Possible keys include:
        - "cvss_v4_0"
        - "cvss_v3_1"
        - "cvss_v3_0"
        - "cvss_v2_0"

    score_strategy : str, optional
        Strategy to select the CVSS score to use. Options are:
        - "first"  : Use the first non-null score as it appears in the CVE data (original field order).
        - "latest" : Use the score from the most recent CVSS version available
                     (v4.0 → v3.1 → v3.0 → v2.0).
        - "mean"   : Compute the arithmetic mean of all available non-null scores.

    Returns
    -------
    dict
        The input `example` dictionary with an added "severity_label" field,
        which can be one of: "Critical", "High", "Medium", "Low", or "Unknown".
    """

    def to_float(value):
        try:
            return float(value) if value is not None else None
        except ValueError:
            return None

    version_priority = ["cvss_v4_0", "cvss_v3_1", "cvss_v3_0", "cvss_v2_0"]

    if score_strategy == "first":
        severity_score = None
        for key, value in example.items():
            if key in version_priority:
                score = to_float(value)
                if score is not None:
                    severity_score = score
                    break

    elif score_strategy == "latest":
        for key in version_priority:
            score = to_float(example.get(key))
            if score is not None:
                severity_score = score
                break
        else:
            severity_score = None

    elif score_strategy == "mean":
        scores = [to_float(example.get(k)) for k in version_priority]
        filtered_scores = [s for s in scores if s is not None]
        severity_score = (
            sum(filtered_scores) / len(filtered_scores) if filtered_scores else None
        )

    else:
        raise ValueError(f"Unknown score_strategy: {score_strategy}")

    if severity_score is None:
        severity_label = "Unknown"
    elif severity_score >= 9.0:
        severity_label = "Critical"
    elif severity_score >= 7.0:
        severity_label = "High"
    elif severity_score >= 4.0:
        severity_label = "Medium"
    else:
        severity_label = "Low"

    example["severity_label"] = severity_label
    return example


def build_model_card(
    template: str,
    *,
    base_model: str,
    dataset_id: str,
    dataset_commit: str | None,
    repo_id: str | None,
    model_revision: str | None,
    model_save_dir: str,
    split_rows: dict[str, tuple[int, int]],
    test_metrics: dict[str, Any],
    test_labels: list[int],
    training_args: TrainingArguments,
    log_history: list[dict[str, Any]],
) -> str:
    """Fill a model card template with the values measured by a training run.

    ``split_rows`` maps a split to its number of rows and of labelled rows.
    ``model_revision`` is the commit of the model on the Hub: it is only known
    after a push, and the usage example is pinned to it when it is given.
    """
    hub_url = "https://huggingface.co"
    model_name = repo_id or Path(model_save_dir).resolve().name

    if dataset_commit:
        dataset_url = f"{hub_url}/datasets/{dataset_id}/tree/{dataset_commit}"
        dataset_revision_text = f"Revision [`{dataset_commit[:7]}`]({dataset_url})"
        model_index_revision = f"\n      revision: {dataset_commit}"
    else:
        dataset_revision_text = "A local copy"
        model_index_revision = ""

    if model_revision:
        example_loading = (
            f'revision = "{model_revision[:7]}"\n'
            "tokenizer = AutoTokenizer.from_pretrained(model_name, revision=revision)\n"
            "model = AutoModelForSequenceClassification.from_pretrained(model_name, revision=revision)"
        )
    else:
        example_loading = (
            "tokenizer = AutoTokenizer.from_pretrained(model_name)\n"
            "model = AutoModelForSequenceClassification.from_pretrained(model_name)"
        )

    # Normal approximation of the 95% confidence interval of the accuracy.
    accuracy = test_metrics["test_accuracy"]
    test_samples = len(test_labels)
    margin = 1.96 * math.sqrt(accuracy * (1 - accuracy) / test_samples)

    support = Counter(test_labels)
    class_rows = []
    for label_name, label_id in SEVERITY_MAPPING.items():
        if f"test_{label_name}_f1" not in test_metrics:
            continue
        class_rows.append(
            f"| {label_name} "
            f"| {test_metrics[f'test_{label_name}_precision']:.4f} "
            f"| {test_metrics[f'test_{label_name}_recall']:.4f} "
            f"| {test_metrics[f'test_{label_name}_f1']:.4f} "
            f"| {support[label_id]:,} |"
        )

    # One row per validation pass, with the last training loss logged before it.
    epoch_rows = []
    best_epoch, best_accuracy, training_loss = None, -1.0, None
    for entry in log_history:
        if "loss" in entry:
            training_loss = entry["loss"]
        if "eval_loss" not in entry:
            continue
        loss = "-" if training_loss is None else f"{training_loss:.4f}"
        epoch_rows.append(
            f"| {entry['epoch']:.1f} | {entry['step']} | {loss} "
            f"| {entry['eval_loss']:.4f} | {entry['eval_accuracy']:.4f} "
            f"| {entry['eval_f1_macro']:.4f} |"
        )
        if entry["eval_accuracy"] > best_accuracy:
            best_epoch, best_accuracy = entry["epoch"], entry["eval_accuracy"]

    hyperparameters = {
        "learning_rate": training_args.learning_rate,
        "train_batch_size": training_args.train_batch_size,
        "eval_batch_size": training_args.eval_batch_size,
        "seed": training_args.seed,
        "optimizer": getattr(training_args.optim, "value", training_args.optim),
        "lr_scheduler_type": getattr(
            training_args.lr_scheduler_type, "value", training_args.lr_scheduler_type
        ),
        "warmup_steps": training_args.warmup_steps,
        "weight_decay": training_args.weight_decay,
        "num_epochs": int(training_args.num_train_epochs),
    }

    files_url = f"{hub_url}/{repo_id}/blob/main" if repo_id else "."
    provenance_files = [
        f"- [`bom.cdx.json`]({files_url}/bom.cdx.json): machine-readable record of the run "
        "([CycloneDX ML-BOM](https://cyclonedx.org/capabilities/mlbom/)): "
        "base model, dataset revision, "
        "metrics, training options and energy use."
    ]
    emissions_text = ""
    emissions = read_emissions_report(model_save_dir)
    if emissions is not None:
        minutes = round(float(emissions["duration"]) / 60)
        hardware = emissions.get("gpu_model") or emissions.get("cpu_model") or "CPU"
        emissions_text = (
            f"\nTraining took {minutes // 60} h {minutes % 60} min on {hardware} "
            f"and used {float(emissions['energy_consumed']):.2f} kWh, "
            f"for {float(emissions['emissions']):.2f} kg CO₂eq\n"
            f"(measured with CodeCarbon, see [`emissions.csv`]({files_url}/emissions.csv)).\n"
        )
        provenance_files.append(
            f"- [`emissions.csv`]({files_url}/emissions.csv): energy use and CO₂ "
            "emissions of the training, measured with "
            "[CodeCarbon](https://codecarbon.io/)."
        )

    versions = {
        "Transformers": "transformers",
        "Pytorch": "torch",
        "Datasets": "datasets",
        "Tokenizers": "tokenizers",
    }

    return template.format(
        base_model=base_model,
        dataset_id=dataset_id,
        repo_id=model_name,
        model_name=model_name.split("/")[-1],
        model_index_revision=model_index_revision,
        example_loading=example_loading,
        dataset_revision_text=dataset_revision_text,
        split_table="\n".join(
            f"| {split} | {rows:,} | {labelled:,} |"
            for split, (rows, labelled) in split_rows.items()
        ),
        hyperparameters="\n".join(
            f"- {name}: {value}" for name, value in hyperparameters.items()
        ),
        best_epoch="unknown" if best_epoch is None else f"{best_epoch:g}",
        emissions_text=emissions_text,
        test_samples=test_samples,
        accuracy=accuracy,
        accuracy_low=accuracy - margin,
        accuracy_high=accuracy + margin,
        f1_macro=test_metrics["test_f1_macro"],
        class_table="\n".join(class_rows),
        epoch_table="\n".join(epoch_rows),
        framework_versions="\n".join(
            f"- {name} {metadata.version(package)}" for name, package in versions.items()
        ),
        vulntrain_version=metadata.version("VulnTrain"),
        provenance_files="\n".join(provenance_files),
    )


def train(
    base_model,
    dataset_id,
    repo_id,
    model_save_dir="./vulnerability-classify",
    push_to_hub=True,
    use_cache=False,
    codecarbon=True,
    dataset_revision=None,
    push_card=True,
):
    # Load dataset from Hugging Face. Resolve the commit first and load exactly
    # that one, so the revision recorded in the ML-BOM is the one the model was
    # trained on.
    dataset_commit = resolve_dataset_revision(dataset_id, dataset_revision)
    logger.info(f"Dataset revision: {dataset_commit or 'unknown'}")
    dataset = load_dataset(dataset_id, revision=dataset_commit or dataset_revision)

    raw_rows = {split: len(dataset[split]) for split in dataset}

    # Map severity labels
    dataset = dataset.map(map_cvss_to_severity)

    # Filter out entries with no severity_label and with unknown keys
    dataset = dataset.filter(lambda x: "severity_label" in x)
    dataset = dataset.filter(lambda x: x["severity_label"] in SEVERITY_MAPPING)

    # Tokenization with labels
    tokenizer = AutoTokenizer.from_pretrained(base_model)
    clamp_tokenizer_max_length(tokenizer, base_model)
    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    def tokenize_function(elem):
        tokenized = tokenizer(
            elem["description"],
            padding="max_length",
            truncation=True,
        )

        # Convert list of severity labels to integers
        tokenized["labels"] = [
            SEVERITY_MAPPING[label] for label in elem["severity_label"]
        ]

        return tokenized

    tokenized_datasets = dataset.map(tokenize_function, batched=True)
    # print(tokenized_datasets["test"])

    # Define model
    num_labels = len(SEVERITY_MAPPING)  # 4 classes

    model = AutoModelForSequenceClassification.from_pretrained(
        base_model,
        num_labels=num_labels,
        id2label={
            v: k for k, v in SEVERITY_MAPPING.items()
        },  # Mapping indices to labels
        label2id=SEVERITY_MAPPING,  # Mapping labels to indices
    )

    # Large models (ai-forever/ruRoberta-large) can collapse to predicting a
    # single class at 3e-5 without warmup: on Vulnerability-FSTEC a104085 the
    # model predicted one class for four of five epochs. They get a lower
    # learning rate and a warmup; the base-size models keep their settings.
    large_model = "large" in base_model.lower()

    # Define training arguments
    training_args = TrainingArguments(
        output_dir=model_save_dir,
        eval_strategy="epoch",
        save_strategy="epoch",
        learning_rate=1e-5 if large_model else 3e-5,
        # A float below 1 is a ratio of the total steps.
        warmup_steps=0.1 if large_model else 0,
        per_device_train_batch_size=8 if "roberta" in base_model else 16,
        per_device_eval_batch_size=8 if "roberta" in base_model else 16,
        num_train_epochs=5,
        weight_decay=0.01,
        logging_steps=10,
        save_total_limit=3,
        load_best_model_at_end=True,
        metric_for_best_model="accuracy",
        greater_is_better=True,
        use_cache=use_cache,
        hub_model_id=repo_id,
    )

    # Select the best checkpoint on the validation split when the dataset has
    # one, so that the test split is only used for the final evaluation.
    eval_split = "validation" if "validation" in tokenized_datasets else "test"
    if eval_split == "test":
        logger.warning("No validation split: checkpoints are selected on test.")

    # Create Trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_datasets["train"],
        eval_dataset=tokenized_datasets[eval_split],
        data_collator=data_collator,
        compute_metrics=compute_metrics,
    )

    # Train model
    tracker = None
    if codecarbon:
        # Save emissions data inside the model directory so it gets pushed to
        # the Hub together with the model (default output_dir is the CWD, which
        # is never uploaded).
        tracker = EmissionsTracker(
            project_name="VulnTrain",
            output_dir=model_save_dir,
            output_file="emissions.csv",
            allow_multiple_runs=True,
        )
        tracker.start()
    try:
        trainer.train()
    finally:
        if tracker is not None:
            tracker.stop()
        model.save_pretrained(model_save_dir)
        tokenizer.save_pretrained(model_save_dir)

    if eval_split == "validation":
        test_metrics = trainer.evaluate(
            tokenized_datasets["test"], metric_key_prefix="test"
        )
        logger.info(f"Test metrics: {test_metrics}")

        # Record what the run used and measured (CycloneDX ML-BOM). The file is
        # in the model directory, so it is uploaded with the model when the run
        # pushes. It needs metrics from a test split that did not select the
        # checkpoint, so it is only written for a dataset with a validation split.
        bom_file = write_ml_bom(
            model_save_dir,
            repo_id=repo_id,
            base_model=base_model,
            dataset_id=dataset_id,
            dataset_revision=dataset_commit,
            task="text-classification",
            license_id="CC-BY-4.0",
            metrics=ml_bom_metrics(test_metrics, "test", list(SEVERITY_MAPPING)),
            properties={
                "cdx:ai-ml:model:hyperparameter:learning_rate": training_args.learning_rate,
                "cdx:ai-ml:model:hyperparameter:warmup_steps": training_args.warmup_steps,
                "cdx:ai-ml:model:hyperparameter:batch_size": training_args.train_batch_size,
                "cdx:ai-ml:model:hyperparameter:num_epochs": int(training_args.num_train_epochs),
                "cdx:ai-ml:model:hyperparameter:weight_decay": training_args.weight_decay,
                "cdx:ai-ml:model:hyperparameter:max_length": tokenizer.model_max_length,
                "vulntrain:training:score_strategy": "first",
                "vulntrain:evaluation:test_samples": len(tokenized_datasets["test"]),
            },
        )
        logger.info(f"ML-BOM written to {bom_file}")

    # The model card reports the same test metrics as the ML-BOM.
    card_path = Path(model_save_dir) / "README.md"
    template_name = CARD_TEMPLATES.get((base_model, dataset_id))
    write_card = None
    if push_card and template_name and eval_split == "validation":
        template = (CARDS_DIR / template_name).read_text()

        def write_card(model_revision=None):
            card_path.write_text(
                build_model_card(
                    template,
                    base_model=base_model,
                    dataset_id=dataset_id,
                    dataset_commit=dataset_commit,
                    repo_id=repo_id,
                    model_revision=model_revision,
                    model_save_dir=model_save_dir,
                    split_rows={
                        split: (raw_rows[split], len(dataset[split]))
                        for split in raw_rows
                    },
                    test_metrics=test_metrics,
                    test_labels=tokenized_datasets["test"]["labels"],
                    training_args=training_args,
                    log_history=trainer.state.log_history,
                )
            )

        # Written before any push, so a local run can be reviewed.
        write_card()
        logger.info(f"Model card written to {card_path}")

    if push_to_hub:
        trainer.push_to_hub()
        tokenizer.push_to_hub(repo_id)

        if tracker is not None and push_emissions_report(model_save_dir, repo_id):
            logger.info(f"Emissions report pushed to {repo_id}")

        if write_card is not None:
            from huggingface_hub import HfApi

            # trainer.push_to_hub() replaced README.md with the card generated
            # by the Trainer. Write ours again, with the usage example pinned
            # to the commit that holds the model, and upload it.
            api = HfApi()
            write_card(api.model_info(repo_id).sha)
            api.upload_file(
                path_or_fileobj=str(card_path),
                path_in_repo="README.md",
                repo_id=repo_id,
                commit_message="Update model card with evaluation metrics",
            )
            logger.info(f"Model card pushed to {repo_id}")


def main():
    parser = argparse.ArgumentParser(
        description="Train a vulnerability classification model with a mapping on the severity."
    )
    parser.add_argument(
        "--base-model",
        dest="base_model",
        default="distilbert-base-uncased",
        choices=[
            "distilbert-base-uncased",
            "roberta-base",
            "ai-forever/ruRoberta-large",
        ],
        help="Base model to use.",
    )
    parser.add_argument(
        "--dataset-id",
        dest="dataset_id",
        default="CIRCL/vulnerability-scores",
        help="Path of the dataset. Local dataset or repository on the HF hub.",
    )
    parser.add_argument(
        "--dataset-revision",
        dest="dataset_revision",
        default=None,
        help="Branch, tag or commit of the dataset on the HF hub (default: the latest commit of the default branch).",
    )
    parser.add_argument(
        "--repo-id",
        dest="repo_id",
        default=None,
        help="The name of the repository you want to push your object to. It should contain your organization name when pushing to a given organization. Required unless --no-push is set.",
    )
    parser.add_argument(
        "--model-save-dir",
        dest="model_save_dir",
        default="results",
        help="The path to a directory where the tokenizer and the model will be saved.",
    )
    parser.add_argument(
        "--no-codecarbon",
        dest="no_codecarbon",
        action="store_true",
        default=False,
        help="Disable CodeCarbon emissions tracking.",
    )
    parser.add_argument(
        "--no-push",
        dest="no_push",
        action="store_true",
        default=False,
        help="Disable pushing the model and tokenizer to Hugging Face Hub.",
    )
    parser.add_argument(
        "--no-card",
        dest="no_card",
        action="store_true",
        default=False,
        help="Keep the model card generated by the Trainer instead of the VulnTrain one.",
    )
    parser.add_argument(
        "--no-cache",
        dest="no_cache",
        action="store_true",
        default=False,
        help="Disable cache for the model during training.",
    )

    args = parser.parse_args()
    if not args.no_push and not args.repo_id:
        parser.error("--repo-id is required unless --no-push is set")

    dir_path = Path(args.model_save_dir)
    if dir_path.exists() and dir_path.is_dir():
        shutil.rmtree(dir_path)

    logger.info(f"Using base model: {args.base_model}")
    logger.info(f"Dataset ID: {args.dataset_id}")
    logger.info(f"Repo ID: {args.repo_id}")
    logger.info(f"Saving model to: {args.model_save_dir}")
    logger.info("Starting the training process…")

    train(
        args.base_model,
        args.dataset_id,
        args.repo_id,
        args.model_save_dir,
        push_to_hub=not args.no_push,
        use_cache=not args.no_cache,
        codecarbon=not args.no_codecarbon,
        dataset_revision=args.dataset_revision,
        push_card=not args.no_card,
    )


if __name__ == "__main__":
    main()
