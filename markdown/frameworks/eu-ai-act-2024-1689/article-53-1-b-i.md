# EU AI Act 2024/1689 - Article-53.1.b.i

- Framework Code: EU-AI-ACT
- Requirement Title: Obligations for providers of general-purpose AI models

## Mapping Notes

enable providers of AI systems to have a good understanding of the capabilities and limitations of the general-purpose AI model and to comply with their obligations pursuant to this Regulation; and

SAF-K8S ML-BOM controls (D6) support model card generation through structured metadata capture: model provenance, training data lineage, resource requirements, and version tracking. However, a complete model card requires substantial application-layer content (intended use descriptions, ethical considerations, bias analysis, per-group performance data) beyond what SAF-K8S metadata captures.

## SAF-K8S Controls

### [SAF-K8S-0604-002 - ML-BOM (ML Bill of Materials) generation](../../controls/SAF-K8S-0604-002.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.4
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation

### [SAF-K8S-0905-006 - Model artifact lifecycle management](../../controls/SAF-K8S-0905-006.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation
