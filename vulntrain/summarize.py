import argparse
import torch
from codecarbon import track_emissions  # type: ignore[import-untyped]
from datasets import load_dataset  # type: ignore[import-untyped]
from transformers import (  # type: ignore[import-untyped]
    AutoModelForCausalLM,
    AutoModelForMaskedLM,
    AutoTokenizer,
    DataCollatorForLanguageModeling,
    Trainer,
    TrainingArguments,
)


# choices:
# - distilbert-base-uncased
# - distilgpt2, gpt2
#
BASE_MODEL = "gpt2"  # distilgpt2, gpt2
DATASET = "circl/vulnerability-dataset"
MODEL_PATH = "./vulnerability"

if torch.cuda.is_available():
    device = torch.device("cuda")
    print("Using CUDA (Nvidia GPU).")
elif torch.backends.mps.is_available():
    device = torch.device("mps")
    print("Using MPS (Apple Silicon GPU).")
else:
    device = torch.device("cpu")
    print("Using CPU.")


def get_datasets(tokenizer):
    dataset = load_dataset(DATASET, split="train")

    def tokenize_function(examples):
        return tokenizer(
            examples["description"],
            padding="max_length",
            truncation=True,
            max_length=512,
        )

    tokenized_datasets = dataset.map(tokenize_function, batched=True)
    return tokenized_datasets.train_test_split(test_size=0.2)


training_args = TrainingArguments(
    output_dir=MODEL_PATH,
    num_train_epochs=3,
    learning_rate=2e-5,
    per_device_train_batch_size=8,
    per_device_eval_batch_size=8,
    warmup_steps=500,
    weight_decay=0.01,
    evaluation_strategy="epoch",
    save_strategy="epoch",
    load_best_model_at_end=True,
    logging_dir="./logs",
)


@track_emissions(project_name="VulnTrain", allow_multiple_runs=True)
def train():
    print(f"Base model {BASE_MODEL}")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)

    if "distilbert" in BASE_MODEL:
        model = AutoModelForMaskedLM.from_pretrained(BASE_MODEL)
    else:
        # problem with missing pading token...
        tokenizer.pad_token = tokenizer.eos_token
        model = AutoModelForCausalLM.from_pretrained(BASE_MODEL)

    model.to(device)

    datasets = get_datasets(tokenizer)

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
        model.save_pretrained(MODEL_PATH)
        tokenizer.save_pretrained(MODEL_PATH)

    trainer.push_to_hub("CIRCL/vuln-model-test")


def main():
    parser = argparse.ArgumentParser(
        description="Train a vulnerability text generation model"
    )
    args = parser.parse_args()
    train()


if __name__ == "__main__":
    main()
