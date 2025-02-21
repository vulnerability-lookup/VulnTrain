from markdown_it import MarkdownIt
from nltk.tokenize import sent_tokenize  # type: ignore[import-untyped]


def sentences(text, num_sentences=5):
    sentences = sent_tokenize(text)[:num_sentences]
    return " ".join(sentences)


def strip_markdown(text):
    md = MarkdownIt()
    parsed = md.parse(text)
    return "".join(token.content for token in parsed if token.type == "inline")
