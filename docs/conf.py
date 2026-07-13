# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "VulnTrain"
copyright = "Computer Incident Response Center Luxembourg (CIRCL) <info@circl.lu>"
author = "Cédric Bonhomme, Léa Ulusan"
release = "3.1.0"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = ["myst_parser", "sphinxcontrib.mermaid"]

# Let ```mermaid fenced code blocks render as diagrams in Sphinx (they already
# render natively on GitHub), so one source works in both.
myst_fence_as_directive = ["mermaid"]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_book_theme"
html_static_path = ["static"]
