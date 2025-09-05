import argparse
import shutil
from pathlib import Path

import torch
from codecarbon import track_emissions
from datasets import load_dataset
from transformers import (
    AutoModelForCausalLM,
    AutoModelForMaskedLM,
    AutoTokenizer,
    DataCollatorForLanguageModeling,
    Trainer,
    TrainingArguments,
)

"""
Create a text generation model for descriptions of vulnerabilities.

Tested with gpt2 and distilgpt2.
"""


def get_datasets(dataset_id, tokenizer):
    # Load dataset from Hugging Face
    dataset = load_dataset(dataset_id, split="train")

    # Tokenization with description
    def tokenize_function(examples):
        return tokenizer(
            examples["description"],
            padding="max_length",
            truncation=True,
            max_length=512,
        )

    tokenized_datasets = dataset.map(tokenize_function, batched=True)
    return tokenized_datasets.train_test_split(test_size=0.2)


@track_emissions(project_name="VulnTrain", allow_multiple_runs=True)
def train(
    base_model, dataset_id, repo_id, model_save_dir="./vulnerability-description"
):
    if torch.cuda.is_available():
        device = torch.device("cuda")
        print("Using CUDA (Nvidia GPU).")
    elif torch.backends.mps.is_available():
        device = torch.device("mps")
        print("Using MPS (Apple Silicon GPU).")
    else:
        device = torch.device("cpu")
        print("Using CPU.")

    tokenizer = AutoTokenizer.from_pretrained(base_model)

    if "distilbert" in base_model:
        model = AutoModelForMaskedLM.from_pretrained(base_model)
    else:
        # problem with missing pading token...
        tokenizer.pad_token = tokenizer.eos_token
        model = AutoModelForCausalLM.from_pretrained(base_model)

    model.to(device)

    datasets = get_datasets(dataset_id, tokenizer)

    training_args = TrainingArguments(
        output_dir=model_save_dir,
        num_train_epochs=3,
        learning_rate=2e-5,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        warmup_steps=500,
        weight_decay=0.01,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        logging_dir="./logs",
        hub_model_id=repo_id,  # Explicitly specify HF model repo
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=datasets["train"],
        eval_dataset=datasets["test"],
        tokenizer=tokenizer,
        data_collator=DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False),
    )

    try:
        trainer.train()
    finally:
        model.save_pretrained(model_save_dir)
        tokenizer.save_pretrained(model_save_dir)

    trainer.push_to_hub()
    tokenizer.push_to_hub(repo_id)


def main():
    parser = argparse.ArgumentParser(
        description="Train a vulnerability text generation model."
    )
    parser.add_argument(
        "--base-model",
        dest="base_model",
        default="gpt2",
        choices=[
            "gpt2",
            "distilgpt2",
            "meta-llama/Llama-3.3-70B-Instruct",
            "distilbert-base-uncased",
        ],
        help="Base model to use.",
    )
    parser.add_argument(
        "--dataset-id",
        dest="dataset_id",
        default="CIRCL/vulnerability",
        help="Path of the dataset. Local dataset or repository on the HF hub.",
    )
    parser.add_argument(
        "--repo-id",
        dest="repo_id",
        required=True,
        help="The name of the repository you want to push your object to. It should contain your organization name when pushing to a given organization.",
    )
    parser.add_argument(
        "--model-save-dir",
        dest="model_save_dir",
        default="results",
        help="The path to a directory where the tokenizer and the model will be saved.",
    )

    args = parser.parse_args()

    dir_path = Path(args.model_save_dir)
    if dir_path.exists() and dir_path.is_dir():
        shutil.rmtree(dir_path)

    print(f"Using base model: {args.base_model}")
    print(f"Dataset ID: {args.dataset_id}")
    print(f"Destination Hugging Face repository ID: {args.repo_id}")
    print(f"Model will be saved to: {args.model_save_dir}")
    print("Starting the training process…")

    train(args.base_model, args.dataset_id, args.repo_id, args.model_save_dir)


if __name__ == "__main__":
    main()
