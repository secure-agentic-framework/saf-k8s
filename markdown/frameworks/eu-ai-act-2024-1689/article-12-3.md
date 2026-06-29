# EU AI Act 2024/1689 - Article-12.3

- Framework Code: EU-AI-ACT
- Requirement Title: Record-keeping

## Mapping Notes

For high-risk AI systems referred to in point 1 (a), of Annex III, the logging capabilities shall provide, at a minimum:

The specific biometric identification logging requirements are application-layer concerns. However, SAF-K8S audit logging infrastructure captures the platform-level events (API calls, model invocations, data access) that form the foundation for these application-level logs.

## SAF-K8S Controls

### [SAF-K8S-1001-007 - Supplemental application-level telemetry for AI workload events](../../controls/SAF-K8S-1001-007.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
