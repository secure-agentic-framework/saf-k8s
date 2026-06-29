# EU AI Act 2024/1689 - Annex-XI.1.2.b

- Framework Code: EU-AI-ACT
- Requirement Title: Technical documentation referred to in Article 53(1), point (a) — technical documentation for providers of general-purpose AI models

## Mapping Notes

the design specifications of the model and training process, including training methodologies and techniques, the key design choices including the rationale and assumptions made; what the model is designed to optimise for and the relevance of the different parameters, as applicable;

SAF-K8S captures training job configurations, pipeline DAGs, data ingestion controls, and processing infrastructure. Training methodology documentation is application-layer, but SAF-K8S provides reproducible training infrastructure records.

## SAF-K8S Controls

### [SAF-K8S-0904-001 - Pipeline orchestrator hardening](../../controls/SAF-K8S-0904-001.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.4
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
