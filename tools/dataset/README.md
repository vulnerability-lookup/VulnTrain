# Dataset checks

Scripts for checking the datasets built with `vulntrain-dataset-generation`.
They are not part of the installed `vulntrain` package.

## Train/test leakage

`check_split_leakage.py` reads the parquet files of a dataset revision and
reports, for each split other than train, how many labelled rows have a
labelled train row with the same description (lower case, whitespace
collapsed) or for the same vulnerability (identifier or `aliases` column). It
also counts the groups that span more than one split and the identifiers
repeated within a source. It only needs `pyarrow` and the standard library.

```bash
hf download CIRCL/vulnerability-scores --repo-type dataset --local-dir vs
python3 tools/dataset/check_split_leakage.py --data-dir vs --json-out leakage.json
```

After a rebuild with the group-aware split, run it with
`--max-shared-groups 0`: it exits with status 1 when any group spans two
splits. `--flags-out` writes one row per test row (no text) marking whether it
has a train twin, to measure a model's accuracy on seen and unseen rows.

Revisions built before the group-aware split have no `aliases` column; pass an
alias file with `--aliases` (`id<TAB>alias,alias` per line) to check aliases
too.

Contributed by [Christian Bucher](https://github.com/christian140903-sudo).
