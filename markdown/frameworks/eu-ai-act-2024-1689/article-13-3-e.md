# EU AI Act 2024/1689 - Article-13.3.e

- Framework Code: EU-AI-ACT
- Requirement Title: Transparency and provision of information to deployers

## Mapping Notes

Validated workload declarations and their observed Kubernetes enforcement can inform the provider's instructions about the configured resource profile. Assess the computational and hardware resources the high-risk AI system needs using evidence representative of that system. SAF-K8S-1007-011 contributes applicable Kubernetes upgrade planning. The provider documents system lifetime and necessary maintenance and care measures separately.

## SAF-K8S Controls

### [SAF-K8S-0304-010 - Pod resource requests and limits specification](../../controls/SAF-K8S-0304-010.md)

- Domain: D03 - Workload and Pod Security
- Knowledge Area: 3.4
- Relation Type: partial
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0604-002 - ML-BOM (ML Bill of Materials) generation](../../controls/SAF-K8S-0604-002.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.4
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation
