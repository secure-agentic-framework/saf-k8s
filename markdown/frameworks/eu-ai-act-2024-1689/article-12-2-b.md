# EU AI Act 2024/1689 - Article-12.2.b

- Framework Code: EU-AI-ACT
- Requirement Title: Record-keeping

## Mapping Notes

facilitating the post-market monitoring referred to in Article 72; and

SAF-K8S observability controls (D10) provide the telemetry infrastructure that feeds post-market monitoring: operational logs, resource metrics, and security events. Full post-market monitoring also requires application-layer event recording (model performance tracking, inference quality metrics) beyond platform telemetry.

## SAF-K8S Controls

### [SAF-K8S-1002-001 - Metric endpoint authentication](../../controls/SAF-K8S-1002-001.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.2
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation

### [SAF-K8S-1002-003 - AI workload telemetry integration into cluster monitoring](../../controls/SAF-K8S-1002-003.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.2
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
