# EU AI Act 2024/1689 - Annex-IV.6

- Framework Code: EU-AI-ACT
- Requirement Title: Technical documentation referred to in Article 11(1)

## Mapping Notes

A description of relevant changes made by the provider to the system through its lifecycle;

SAF-K8S GitOps and supply chain controls (D6) track infrastructure-level changes via version control, container image tagging, deployment history, and audit logs. However, lifecycle changes also include application-layer changes (model architecture, training data, hyperparameters) that may not be captured by platform controls alone.

## SAF-K8S Controls

### [SAF-K8S-1001-016 - Audit policy coverage for AI-specific resource and workflow events](../../controls/SAF-K8S-1001-016.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.1
- Relation Type: partial
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-1007-005 - Change management for production AI model deployments](../../controls/SAF-K8S-1007-005.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.7
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
