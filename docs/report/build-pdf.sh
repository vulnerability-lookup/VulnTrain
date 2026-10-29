#!/bin/sh
# Build the PDF version of docs/vulnerability-scores-leakage-report.md.
#
# Requires pandoc, LuaLaTeX and the Eisvogel template
# (https://github.com/Wandmalfarbe/pandoc-latex-template).
# Run from the repository root: sh docs/report/build-pdf.sh
set -e

# Title page background (two passes for the page-relative positions).
(
  cd docs/report
  for pass in 1 2; do
    lualatex -interaction=nonstopmode -halt-on-error cover.tex > /dev/null
  done
  rm -f cover.aux cover.log
)

pandoc docs/vulnerability-scores-leakage-report.md \
  --metadata-file=docs/report/vulnerability-scores-leakage.yaml \
  --lua-filter=docs/report/short-title.lua \
  --from=markdown-implicit_figures \
  --template=eisvogel \
  --pdf-engine=lualatex \
  --number-sections \
  --resource-path=docs \
  -o docs/report/vulnerability-scores-leakage-report.pdf
