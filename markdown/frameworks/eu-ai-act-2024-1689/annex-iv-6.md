# EU AI Act 2024/1689 - Annex-IV.6

- Framework Code: EU-AI-ACT
- Requirement Title: Technical documentation referred to in Article 11(1)

## Mapping Notes

A description of relevant changes made by the provider to the system through its lifecycle;

SAF-K8S GitOps controls (D6), audit logging (D10), and deployment tracking provide change management infrastructure for platform-level changes. Kubernetes natively records deployment revisions, ConfigMap changes, and Secret rotations. However, comprehensive AI system change tracking also requires application-layer change logging (model updates, dataset changes, algorithm modifications).

## SAF-K8S Controls

### [SAF-K8S-0905-006 - Model artifact lifecycle management](../../controls/SAF-K8S-0905-006.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation

### [SAF-K8S-1001-016 - Audit policy coverage for AI-specific resource and workflow events](../../controls/SAF-K8S-1001-016.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation

### [SAF-K8S-1007-005 - Change management for production AI model deployments](../../controls/SAF-K8S-1007-005.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.7
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
