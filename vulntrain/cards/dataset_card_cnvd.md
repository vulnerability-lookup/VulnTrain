---
language:
- zh
license: cc-by-4.0
tags:
- vulnerability
- cybersecurity
- cnvd
- severity-classification
size_categories:
- 100K-1M
---

# Vulnerability-CNVD

Vulnerability descriptions and severity labels from the [China National Vulnerability Database (CNVD)](https://www.cnvd.org.cn/), extracted via [Vulnerability-Lookup](https://vulnerability.circl.lu).

## Dataset structure

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | CNVD identifier (e.g., CNVD-2025-03529) |
| `title` | string | Vulnerability title in Chinese |
| `description` | string | Vulnerability description in Chinese |
| `severity` | string | Severity level: 高 (High), 中 (Medium), or 低 (Low) |
| `cve_id` | string | Corresponding CVE identifier, if available (empty string if none) |

## Severity distribution

The dataset is imbalanced:

| Severity | Chinese | Approximate share |
|----------|---------|-------------------|
| High | 高 | ~36% |
| Medium | 中 | ~55% |
| Low | 低 | ~9% |

## CVE overlap

Approximately 81% of CNVD entries have a corresponding CVE identifier. The overlap rate varies by year:

- **2020-2021**: 68-69% CVE mapping rate
- **2022+**: 91-97% CVE mapping rate

The ~19% of CNVD-only entries are concentrated in Chinese domestic software (PHP CMS, ERP systems). Western vendors (Adobe, Microsoft, IBM, Cisco) are largely absent from the CNVD-only subset.

## Coverage and provenance

CNVD reserves 50,000-100,000 vulnerability IDs per year but publishes full details for only a fraction. The publication rate has declined significantly:

- **2015**: ~94% of reserved IDs have published details
- **2023**: ~4% of reserved IDs have published details

This decline coincides with China's Regulations on the Management of Security Vulnerabilities (RMSV), effective September 2021.

Entries without a description or severity label are excluded from this dataset.

## Duplicate descriptions

CNVD reuses boilerplate descriptions across different vulnerability IDs (product-specific entries sharing the same text). When using this dataset for train/test splits, **split on unique description text** rather than on IDs to avoid data leakage. See [VulnTrain#19](https://github.com/vulnerability-lookup/VulnTrain/issues/19) for details.

## Source

- **Data source**: [Vulnerability-Lookup](https://vulnerability.circl.lu) API
- **Extraction tool**: [VulnTrain](https://github.com/vulnerability-lookup/VulnTrain)
- **Original source**: [CNVD](https://www.cnvd.org.cn/)

## Related models

- [CIRCL/vulnerability-severity-classification-chinese-macbert-base](https://huggingface.co/CIRCL/vulnerability-severity-classification-chinese-macbert-base) — severity classifier trained on this dataset

## References

- [Vulnerability-Lookup](https://vulnerability.circl.lu) — the vulnerability data source
- [VulnTrain](https://github.com/vulnerability-lookup/VulnTrain) — training pipeline
- [ML-Gateway](https://github.com/vulnerability-lookup/ML-Gateway) — inference API
- [VLAI paper](https://arxiv.org/abs/2507.03607) — Bonhomme, C., Dulaunoy, A. (2025)
