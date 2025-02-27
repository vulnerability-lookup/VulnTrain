import argparse

from transformers import pipeline


# https://discuss.huggingface.co/t/how-to-set-max-length-properly-when-using-pipeline/125714


def main():
    """Instantiates a generator based on a model optimized for text generation and
    send a task (prompt) to the model.
    """
    parser = argparse.ArgumentParser(
        description="Validate a text generation model for vulnerabilities."
    )
    parser.add_argument(
        "--model",
        dest="model",
        help="The model to use.",
        default="CIRCL/vuln-model-test",
    )
    parser.add_argument(
        "--prompt",
        dest="prompt",
        help="The prompt for the generator.",
        default="A new vulnerability in OpenSSL allows attackers to",
    )

    args = parser.parse_args()

    # Load the model from Hugging Face
    generator = pipeline("text-generation", model=args.model)

    print(generator(args.prompt, max_length=100))


if __name__ == "__main__":
    main()
