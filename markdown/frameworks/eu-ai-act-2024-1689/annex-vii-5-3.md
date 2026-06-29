# EU AI Act 2024/1689 - Annex-VII.5.3

- Framework Code: EU-AI-ACT
- Requirement Title: Conformity based on an assessment of the quality management system and an assessment of the technical documentation

## Mapping Notes

The notified body shall carry out periodic audits to make sure that the provider maintains and applies the quality management system and shall provide the provider with an audit report. In the context of those audits, the notified body may carry out additional tests of the AI systems for which a Union technical documentation assessment certificate was issued.

SAF-K8S audit logging (D10) and RBAC (D4) can provide read-only auditor access to platform evidence. Granting physical or organizational access for surveillance is outside SAF-K8S scope.

## SAF-K8S Controls

### [SAF-K8S-0401-001 - RBAC least-privilege design](../../controls/SAF-K8S-0401-001.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-1001-017 - Audit capture of admission, authorization, and privileged API decisions for AI workloads](../../controls/SAF-K8S-1001-017.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation

### [SAF-K8S-1006-004 - Automated audit readiness for Kubernetes AI platforms](../../controls/SAF-K8S-1006-004.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.6
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
