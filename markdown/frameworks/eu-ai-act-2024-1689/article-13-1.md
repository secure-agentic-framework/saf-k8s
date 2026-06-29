# EU AI Act 2024/1689 - Article-13.1

- Framework Code: EU-AI-ACT
- Requirement Title: Transparency and provision of information to deployers

## Mapping Notes

High-risk AI systems shall be designed and developed in such a way as to ensure that their operation is sufficiently transparent to enable deployers to interpret a system’s output and use it appropriately. An appropriate type and degree of transparency shall be ensured with a view to achieving compliance with the relevant obligations of the provider and deployer set out in Section 3.

SAF-K8S supports operational transparency through audit logging (D10), model provenance (D9 KA 9.5), and inference telemetry (D10 KA 10.2). The design of interpretable AI outputs is an application-layer concern.

## SAF-K8S Controls

### [SAF-K8S-0905-009 - Model provenance verification at deployment](../../controls/SAF-K8S-0905-009.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-1001-016 - Audit policy coverage for AI-specific resource and workflow events](../../controls/SAF-K8S-1001-016.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation

### [SAF-K8S-1002-003 - AI workload telemetry integration into cluster monitoring](../../controls/SAF-K8S-1002-003.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.2
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
