---
language:
- fr
license: cc-by-4.0
tags:
- vulnerability
- cybersecurity
- cert-fr
- severity-classification
size_categories:
- 10K<n<100K
---

# Vulnerability-CERT-FR

Security bulletins in French published by [CERT-FR](https://www.cert.ssi.gouv.fr/) (alerts and advisories, including the earlier CERTA bulletins), extracted via [Vulnerability-Lookup](https://vulnerability.circl.lu) and labelled with the CVSS scores of the CVEs they reference.

## Dataset structure

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | CERT-FR reference (e.g., CERTFR-2026-AVI-1359) |
| `title` | string | Bulletin title in French |
| `description` | string | Bulletin summary in French, with HTML and Markdown markup removed |
| `risks` | list of strings | Risks listed by CERT-FR (e.g., "Exécution de code arbitraire à distance") |
| `published` | string | Initial release date of the bulletin |
| `cve_ids` | list of strings | CVEs referenced by the bulletin |
| `cvss_scores` | list of floats | CVSS base score of each CVE in `cve_ids` (null if the CVE has no score) |
| `cvss_versions` | list of strings | CVSS version of each score in `cvss_scores` (e.g., `cvss_v3_1`) |
| `cvss_max` | float | Highest score in `cvss_scores` |
| `cvss_mean` | float | Mean of the available scores in `cvss_scores` |
| `v2_only` | bool | True when all available scores are CVSS v2.0 |
| `source` | string | `certfr_alerte` or `certfr_avis` |

## Labelling

CERT-FR bulletins do not carry a severity rating. Each bulletin is scored from the CVEs it references:

- The score of a CVE is taken from its CNA record, or from NVD when the CNA provides none. When several CVSS versions are available, v3.1 is preferred, then v3.0, v4.0 and v2.0.
- `cvss_max` is the recommended label: bulletin summaries and risks describe the most severe impact among the referenced vulnerabilities, which the mean tends to dilute.

Only bulletins referencing between 1 and 10 CVEs, with a score for at least 80% of them, and with a non-empty summary are kept. Larger bulletins are usually vendor patch roll-ups whose maximum score says little about the text.

## Severity distribution

Using `cvss_max` and the CVSS v3 thresholds (Low < 4.0 ≤ Medium < 7.0 ≤ High < 9.0 ≤ Critical):

| Severity | All bulletins | Excluding `v2_only` |
|----------|---------------|---------------------|
| Low | 205 (2.0%) | 79 (1.2%) |
| Medium | 2,702 (25.9%) | 1,321 (19.5%) |
| High | 4,549 (43.6%) | 3,620 (53.4%) |
| Critical | 2,979 (28.5%) | 1,760 (26.0%) |
| **Total** | **10,435** | **6,780** |

Alerts (`certfr_alerte`) account for 258 bulletins, advisories (`certfr_avis`) for the rest.

## CVSS v2

Bulletins published before 2016 mostly reference CVEs scored only with CVSS v2.0 (`v2_only`), which has no Critical rating. Applying CVSS v3 thresholds to them overestimates the share of Critical labels. Depending on the use case, either filter them out or map their scores with the CVSS v2 thresholds (Low < 4.0 ≤ Medium < 7.0 ≤ High).
