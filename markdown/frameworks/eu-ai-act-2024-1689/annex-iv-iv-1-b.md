# EU AI Act 2024/1689 - Annex-IV:IV(1)(b)

- Framework Code: EU-AI-ACT
- Requirement Title: Technical Documentation Referred to in Article 11(1)

## Mapping Notes

A description of the elements of the AI system and of the process for its development, including the methods and techniques used for its development, training and validation, as well as any pre-trained systems or tools used and how these were obtained.

SAF-K8S supply chain controls (D6) track ML-BOMs, model provenance, and container image lineage. Training pipeline orchestration metadata is captured via Kubernetes job records. Full development process documentation is organizational.

## SAF-K8S Controls

### [SAF-K8S-0604-001 - SBOM generation for container and AI artifacts](../../controls/SAF-K8S-0604-001.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.4
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
