# EU AI Act 2024/1689 - Annex-XI:XI(1)(d)

- Framework Code: EU-AI-ACT
- Requirement Title: Technical Documentation for Providers of General-Purpose AI Models Referred to in Article 53(1)(a)

## Mapping Notes

Information about the training data used, including information about the main characteristics and sources of the data, a general description of the training data, and a description of the steps taken to ensure the quality of the data.

SAF-K8S D9 controls manage training data pipeline security, storage access controls, and data integrity verification (checksums, immutable storage). Data documentation, source descriptions, and quality narratives are application-layer deliverables.

## SAF-K8S Controls

### [SAF-K8S-0906-002 - Large-scale data integrity verification](../../controls/SAF-K8S-0906-002.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.6
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
