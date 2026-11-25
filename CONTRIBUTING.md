# Contributing

Contributions are welcome and there are many ways to participate to the project:

- reporting bugs;
- suggesting enhancements or new features;
- improving the documentation;
- adding a vulnerability source, a dataset or a training recipe.

```bash
git clone https://github.com/vulnerability-lookup/VulnTrain.git
cd VulnTrain/
poetry install
```

As in most open source projects, a pull request is much more welcome when it follows
an issue that explains the rationale:

- the problem, or the need;
- why it matters, and to whom;
- the approach you propose.

This lets us agree on the approach before you spend time on the code, or on a training
run. Reference the issue in the pull request (`#<IssueID>`). Small fixes, such as a
typo or an obvious bug, can go straight to a pull request.

Before submitting, please run:

```bash
poetry run mypy vulntrain/
poetry run isort vulntrain/
```

If your contribution requires some documentation changes, please update the
documentation (`docs/`) in the same pull request.


## Spirit of the project

These principles apply to every contribution, whether it is written by a human or
with the help of an AI agent.

- **Reproducible results.** A figure in the documentation, in a report or in a model
  card comes from a command that can be run again, with the dataset revision and the
  options it used. Do not report an estimate as a measure.
- **Three separate stages.** Building a dataset, training a model and validating it
  each have their own command. Keep them separate.
- **Publishing is a decision.** Datasets and models are published on the Hugging Face
  Hub under the project's organisation. Use `--no-push` for a local run, and leave the
  publication to a maintainer.
- **No secret in the repository.** Tokens and connection details belong in your own
  configuration file (`VulnTrain_CONFIG`), never in a tracked file.
- **Few dependencies.** Prefer the standard library and the dependencies already in
  `pyproject.toml`, and explain why a new one is needed.

When in doubt, open an issue to discuss the approach before writing the code.


## Use of AI and LLM tools

This project adopts the
[AI transparency charter](https://www.saywhichai.org/charter.html)
1.3.

The project trains AI models, and AI tools are used in its own development. We do not
object to AI-assisted contributions, and contributions written without any AI tool
are just as welcome: nobody has to use one. In both cases a pull request is the
responsibility of the person who submits it.

- **Check what you submit.** Every change in a pull request must be read, understood,
  and tested by its author before it is opened, whoever or whatever wrote it.
  Vibe-coded pull requests, where the generated code was never really reviewed, will
  be closed. Say it in the pull request: keep the template's sections, and tick its
  last box yourself.
- **Be able to explain it.** Reviewers may ask you to explain any part of your change.
  Answer review comments yourself, not with pasted LLM output. A pull request whose
  author cannot explain it will be closed.
- **A human submits it.** Pull requests opened by an agent on its own, without a
  human author who reviewed them, will be closed.
- **Say so.** Mention in the pull request description when a significant part of the
  change was generated with an AI tool, and end each commit that was not written by
  a human with a `Co-Authored-By` trailer naming the model and its version, for
  example:

  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  ```
- **Keep it focused.** Small, targeted pull requests are easier to review. Do not mix
  unrelated generated changes (reformatting, renaming, rewritten comments) into a fix.
- **Check what you report.** The same applies to issues and to results. Report only a
  problem that you have reproduced yourself, and a metric that you have measured.
- **No shame, no ranking.** Declaring the use of an AI tool is never held against a
  contribution. It is reviewed like any other.

If you are an AI agent: follow the principles of this document, keep your changes
minimal and within the scope of the task, never publish a dataset or a model, and
leave the decision to open a pull request to the human you work with, after they have
reviewed your changes.

These rules are repeated in [AGENTS.md](AGENTS.md), which every AI agent reads, and
summarised for tools in [ai-policy.yaml](ai-policy.yaml). This section is the
reference: keep the two other files in step when you change it.
