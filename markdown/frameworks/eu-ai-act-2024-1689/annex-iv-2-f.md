# EU AI Act 2024/1689 - Annex-IV.2.f

- Framework Code: EU-AI-ACT
- Requirement Title: Technical documentation referred to in Article 11(1)

## Mapping Notes

where applicable, a detailed description of pre-determined changes to the AI system and its performance, together with all the relevant information related to the technical solutions adopted to ensure continuous compliance of the AI system with the relevant requirements set out in Chapter III, Section 2;

Its statement directly addresses pre-determined changes and continuous compliance: continuous-learning systems get update authorization workflows and drift monitoring, while train-verify-lock systems get integrity monitoring and deployment-time signature verification, all enforced via admission control and runtime policy. This is exactly the kind of 'technical solution adopted to ensure continuous compliance' for systems with anticipated changes, though documenting it across all Chapter III Section 2 requirements remains organizational.

## SAF-K8S Controls

### [SAF-K8S-0905-015 - AI system control profile enforcement](../../controls/SAF-K8S-0905-015.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-1001-016 - Audit policy coverage for AI-specific resource and workflow events](../../controls/SAF-K8S-1001-016.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.1
- Relation Type: partial
- Strength: weak
- Applicability: required
- Strength Reason Code: partial-control-coverage
