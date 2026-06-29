# EU AI Act 2024/1689 - Annex-VI.3

- Framework Code: EU-AI-ACT
- Requirement Title: Conformity assessment procedure based on internal control

## Mapping Notes

The provider examines the information contained in the technical documentation in order to assess the compliance of the AI system with the relevant essential requirements set out in Chapter III, Section 2.

SAF-K8S controls map to several Chapter III Section 2 requirements (cybersecurity per Article 15, logging per Article 12, risk management infrastructure per Article 9). SAF-K8S provides technical evidence of conformity for platform-layer requirements.

## SAF-K8S Controls

### [SAF-K8S-0401-001 - RBAC least-privilege design](../../controls/SAF-K8S-0401-001.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0501-001 - Default deny ingress and egress network policies](../../controls/SAF-K8S-0501-001.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0604-001 - SBOM generation for container and AI artifacts](../../controls/SAF-K8S-0604-001.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.4
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

### [SAF-K8S-1006-001 - Regulatory compliance mapping for Kubernetes AI platforms](../../controls/SAF-K8S-1006-001.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.6
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-1007-005 - Change management for production AI model deployments](../../controls/SAF-K8S-1007-005.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.7
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
