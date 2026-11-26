# EU AI Act 2024/1689 - Article-15.1

- Framework Code: EU-AI-ACT
- Requirement Title: Accuracy, robustness and cybersecurity

## Mapping Notes

Runtime monitoring evidence supports the cybersecurity contribution for scoped components and lifecycle activities.

## SAF-K8S Controls

### [SAF-K8S-0204-001 - Runtime security tool deployment for syscall and network monitoring](../../controls/SAF-K8S-0204-001.md)

- Domain: D02 - Node, Runtime, and OS Security
- Knowledge Area: 2.4
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: n/a

### [SAF-K8S-0301-001 - Pod Security Standards level assignment](../../controls/SAF-K8S-0301-001.md)

- Domain: D03 - Workload and Pod Security
- Knowledge Area: 3.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation

### [SAF-K8S-0604-001 - SBOM generation for container and AI artifacts](../../controls/SAF-K8S-0604-001.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.4
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
