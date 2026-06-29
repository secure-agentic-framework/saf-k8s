# EU AI Act 2024/1689 - Annex-IV.2.b

- Framework Code: EU-AI-ACT
- Requirement Title: Technical documentation referred to in Article 11(1)

## Mapping Notes

the design specifications of the system, namely the general logic of the AI system and of the algorithms; the key design choices including the rationale and assumptions made, including with regard to persons or groups of persons in respect of who, the system is intended to be used; the main classification choices; what the system is designed to optimise for, and the relevance of the different parameters; the description of the expected output and output quality of the system; the decisions about any possible trade-off made regarding the technical solutions adopted to comply with the requirements set out in Chapter III, Section 2;

SAF-K8S captures training job configurations, resource allocations, hyperparameter tracking via experiment management integration, and validation pipeline results. Methodology documentation is application-layer, but SAF-K8S provides infrastructure for reproducible training and validation artifact management.

## SAF-K8S Controls

### [SAF-K8S-0604-002 - ML-BOM (ML Bill of Materials) generation](../../controls/SAF-K8S-0604-002.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.4
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation

### [SAF-K8S-0901-003 - Checkpoint security](../../controls/SAF-K8S-0901-003.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
