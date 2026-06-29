# EU AI Act 2024/1689 - Annex-IV.2.g

- Framework Code: EU-AI-ACT
- Requirement Title: Technical documentation referred to in Article 11(1)

## Mapping Notes

the validation and testing procedures used, including information about the validation and testing data used and their main characteristics; metrics used to measure accuracy, robustness and compliance with other relevant requirements set out in Chapter III, Section 2, as well as potentially discriminatory impacts; test logs and all test reports dated and signed by the responsible persons, including with regard to pre-determined changes as referred to under point (f);

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
