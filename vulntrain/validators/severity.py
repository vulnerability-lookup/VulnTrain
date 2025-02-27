from transformers import AutoModelForSequenceClassification, AutoTokenizer
import torch

labels = ["low", "medium", "high", "critical"]


def main():
    # Load model and tokenizer
    model_name = "CIRCL/vulnerability-severity-classification-distilbert-base-uncased"
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name)
    model.eval()

    vuln_summaries = [
        "This vulnerability allows remote attackers to execute arbitrary code.",
        "Local privilege escalation due to improper access control.",
        "A buffer overflow in the kernel can lead to a system crash.",
        "app/Model/Attribute.php in MISP before 2.4.198 ignores an ACL during a GUI attribute search.",
        "allows attackers to cause a Denial of Service (DoS) when receiving a specially crafted SIP message.",
        "an unauthenticated threat actor can execute arbitrary commands on the underlying operating system",
        "The function dns_copy_qname in dns_pack.c performs performs a memcpy operation with an untrusted field and does not check if the source buffer is large enough to contain the copied data.",
        "langchain_experimental 0.0.14 allows an attacker to bypass the CVE-2023-36258 fix and execute arbitrary code via the PALChain in the python exec method.",
    ]

    inputs = tokenizer(
        vuln_summaries, padding=True, truncation=True, return_tensors="pt"
    )
    with torch.no_grad():
        predictions = model(**inputs).logits  # Get raw logits

    predicted_classes = torch.argmax(predictions, dim=-1)
    for text, pred in zip(vuln_summaries, predicted_classes):
        print(f"Text: {text}\nPredicted severity: {labels[pred.item()]}\n")

        # Predicted severity:
        # predicted_class = torch.argmax(pred, dim=-1).item()
        # print("Predicted severity:", labels[predicted_class]))


if __name__ == "__main__":
    main()
