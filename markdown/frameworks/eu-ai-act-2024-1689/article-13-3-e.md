# EU AI Act 2024/1689 - Article-13.3.e

- Framework Code: EU-AI-ACT
- Requirement Title: Transparency and provision of information to deployers

## Mapping Notes

the computational and hardware resources needed, the expected lifetime of the high-risk AI system and any necessary maintenance and care measures, including their frequency, to ensure the proper functioning of that AI system, including as regards software updates;

SAF-K8S-0304-010 supplies declared Pod resource inputs. SAF-K8S-1007-011 covers cluster, node and add-on upgrade planning relevant to infrastructure maintenance. These are inputs to the provider's instructions covering actual hardware needs, system lifetime and applicable maintenance.

## SAF-K8S Controls

### [SAF-K8S-0304-010 - Pod resource requests and limits specification](../../controls/SAF-K8S-0304-010.md)

- Domain: D03 - Workload and Pod Security
- Knowledge Area: 3.4
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0604-002 - ML-BOM (ML Bill of Materials) generation](../../controls/SAF-K8S-0604-002.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.4
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation
