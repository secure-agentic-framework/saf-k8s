# EU AI Act 2024/1689 - Annex-IV.1.c

- Framework Code: EU-AI-ACT
- Requirement Title: Technical documentation referred to in Article 11(1)

## Mapping Notes

Version and lifecycle records can inform the documented platform versions and update requirements when Kubernetes is relevant to the in-scope AI system. Link applicable version records to that system's technical documentation.

## SAF-K8S Controls

### [SAF-K8S-0104-020 - Kubernetes supported version window compliance](../../controls/SAF-K8S-0104-020.md)

- Domain: D01 - Control Plane and Cluster Hardening
- Knowledge Area: 1.4
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0202-003 - Container runtime patching and version management](../../controls/SAF-K8S-0202-003.md)

- Domain: D02 - Node, Runtime, and OS Security
- Knowledge Area: 2.2
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0606-029 - GitOps deployed package and version metadata retention](../../controls/SAF-K8S-0606-029.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.6
- Relation Type: partial
- Strength: strong
- Applicability: required
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0701-008 - Training data and model artifact version tracking for reproducibility](../../controls/SAF-K8S-0701-008.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: partial-control-coverage
