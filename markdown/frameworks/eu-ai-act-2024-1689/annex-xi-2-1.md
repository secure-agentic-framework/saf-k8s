# EU AI Act 2024/1689 - Annex-XI.2.1

- Framework Code: EU-AI-ACT
- Requirement Title: Technical documentation referred to in Article 53(1), point (a) — technical documentation for providers of general-purpose AI models

## Mapping Notes

A detailed description of the evaluation strategies, including evaluation results, on the basis of available public evaluation protocols and tools or otherwise of other evaluation methodologies. Evaluation strategies shall include evaluation criteria, metrics and the methodology on the identification of limitations.

SAF-K8S CI/CD pipeline controls (D6) enforce security testing gates, vulnerability scanning, and automated evaluation pipelines. However, model evaluation processes (accuracy, fairness, robustness testing) go beyond security scanning and require application-layer test design and analysis.

## SAF-K8S Controls

### [SAF-K8S-0601-008 - CI/CD build-time container image vulnerability scanning](../../controls/SAF-K8S-0601-008.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0606-011 - CI build-time security gate enforcement](../../controls/SAF-K8S-0606-011.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.6
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-1002-003 - AI workload telemetry integration into cluster monitoring](../../controls/SAF-K8S-1002-003.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.2
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-1003-001 - STRIDE threat modeling for Kubernetes AI systems](../../controls/SAF-K8S-1003-001.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.3
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
