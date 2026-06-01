# EU AI Act 2024/1689 - Annex-IV:IV(13)

- Framework Code: EU-AI-ACT
- Requirement Title: Technical Documentation Referred to in Article 11(1)

## Mapping Notes

A detailed description of the measures put in place for the purpose of human oversight, in accordance with Article 14.

SAF-K8S RBAC (D4), audit logging (D10), and dashboard infrastructure support human oversight tooling. The specific human oversight measures and procedures are organizational, but SAF-K8S provides the technical access control and monitoring backbone.

## SAF-K8S Controls

### [SAF-K8S-0401-001 - RBAC least-privilege design](../../controls/SAF-K8S-0401-001.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0401-002 - RBAC permission audit and analysis](../../controls/SAF-K8S-0401-002.md)

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
