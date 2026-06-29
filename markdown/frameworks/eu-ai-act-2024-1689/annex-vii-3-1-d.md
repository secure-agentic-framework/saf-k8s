# EU AI Act 2024/1689 - Annex-VII.3.1.d

- Framework Code: EU-AI-ACT
- Requirement Title: Conformity based on an assessment of the quality management system and an assessment of the technical documentation

## Mapping Notes

the documentation concerning the quality management system which shall cover all the aspects listed under Article 17;

SAF-K8S generates technical documentation artifacts referenced in Annex IV (architecture records, cybersecurity controls, logging configurations, change tracking). These form a subset of the information package submitted with the application.

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

### [SAF-K8S-1001-016 - Audit policy coverage for AI-specific resource and workflow events](../../controls/SAF-K8S-1001-016.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation
