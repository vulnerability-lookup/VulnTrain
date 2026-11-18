## Generic requirements in order to contribute to VulnTrain:

* Read the [contribution guide](https://github.com/vulnerability-lookup/VulnTrain/blob/main/CONTRIBUTING.md), including the rules on AI-assisted contributions
* One Pull Request per fix/feature/change/...
* Keep the amount of commits per PR as small as possible
* Always make sure it is mergeable in the default branch
* Please make sure `poetry run mypy vulntrain/` passes
* Keep the sections below, fill them in, and tick the last box yourself: it is your own statement, not your AI tool's


#### What does it do?

If it fixes an existing issue, please use github syntax: `#<IssueID>`


#### Questions

- [ ] Does it change a published dataset or model (its format, its labels, its metrics)?
- [ ] Does it require a change in the configuration?
- [ ] Was a significant part of it generated with an AI tool? (If so, the commits carry a `Co-Authored-By` trailer naming the model.)
- [ ] I have read, understood and tested every change in this pull request, and I can explain it.
