# EU AI Act 2024/1689 - Annex-IV.1.c

- Framework Code: EU-AI-ACT
- Requirement Title: Technical documentation referred to in Article 11(1)

## Mapping Notes

the versions of relevant software or firmware, and any requirements related to version updates;

The control keeps clusters within the active support window, providing version-currency/update-requirement evidence for the underlying Kubernetes platform, but only tangentially relates to documenting the AI system's own software versions.

## SAF-K8S Controls

### [SAF-K8S-0104-020 - Kubernetes supported version window compliance](../../controls/SAF-K8S-0104-020.md)

- Domain: D01 - Control Plane and Cluster Hardening
- Knowledge Area: 1.4
- Relation Type: partial
- Strength: weak
- Applicability: required
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0202-003 - Container runtime patching and version management](../../controls/SAF-K8S-0202-003.md)

- Domain: D02 - Node, Runtime, and OS Security
- Knowledge Area: 2.2
- Relation Type: partial
- Strength: moderate
- Applicability: required
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
