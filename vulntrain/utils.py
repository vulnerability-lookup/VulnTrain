from nltk.tokenize import sent_tokenize


def sentences(text, num_sentences=5):
    sentences = sent_tokenize(text)[:num_sentences]
    return " ".join(sentences)
