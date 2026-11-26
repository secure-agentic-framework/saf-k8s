# EU AI Act 2024/1689 - Annex-XI.2.1

- Framework Code: EU-AI-ACT
- Requirement Title: Technical documentation referred to in Article 53(1), point (a) — technical documentation for providers of general-purpose AI models

## Mapping Notes

This promotion gate can contribute a release-control step if its required evidence includes the applicable Annex XI evaluation documentation and binds it to the exact model artifact and revisions. The reference fixture only demonstrates deny/allow decisions for fictional source-analysis, component-analysis, CI secret-detection, and artifact-check records. It does not produce or assess model evaluation strategies, evaluation results, criteria, metrics, or limitations.

## SAF-K8S Controls

### [SAF-K8S-0606-011 - CI build-time security gate enforcement](../../controls/SAF-K8S-0606-011.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.6
- Relation Type: partial
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

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
