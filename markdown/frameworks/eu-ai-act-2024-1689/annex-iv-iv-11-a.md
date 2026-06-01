# EU AI Act 2024/1689 - Annex-IV:IV(11)(a)

- Framework Code: EU-AI-ACT
- Requirement Title: Technical Documentation Referred to in Article 11(1)

## Mapping Notes

A detailed description of the training and validation data sets used, including their main characteristics, a description of any data pre-processing measures, e.g. annotation, labelling, cleaning, enrichment and aggregation.

SAF-K8S D9 controls manage training data pipeline security, storage access controls, and data integrity verification. Data pre-processing documentation is application-layer, but SAF-K8S enforces data provenance tracking and immutable storage controls.

## SAF-K8S Controls

### [SAF-K8S-0906-002 - Large-scale data integrity verification](../../controls/SAF-K8S-0906-002.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.6
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
