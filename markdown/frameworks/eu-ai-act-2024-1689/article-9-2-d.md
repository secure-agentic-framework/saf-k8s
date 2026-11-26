# EU AI Act 2024/1689 - Article-9.2.d

- Framework Code: EU-AI-ACT
- Requirement Title: Risk management system

## Mapping Notes

the adoption of appropriate and targeted risk management measures designed to address the risks identified pursuant to point (a).

SAF-K8S controls ARE risk management measures for infrastructure-level risks: network policies, workload isolation, access controls, supply chain integrity, and runtime security all address identified risks.

## SAF-K8S Controls

### [SAF-K8S-0301-001 - Pod Security Standards level assignment](../../controls/SAF-K8S-0301-001.md)

- Domain: D03 - Workload and Pod Security
- Knowledge Area: 3.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match

### [SAF-K8S-0401-001 - RBAC least-privilege design](../../controls/SAF-K8S-0401-001.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0601-008 - CI/CD build-time container image vulnerability scanning](../../controls/SAF-K8S-0601-008.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.1
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: n/a
