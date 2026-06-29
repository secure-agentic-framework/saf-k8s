# EU AI Act 2024/1689 - Article-12.3.a

- Framework Code: EU-AI-ACT
- Requirement Title: Record-keeping

## Mapping Notes

recording of the period of each use of the system (start date and time and end date and time of each use);

The specific biometric identification logging requirements are application-layer concerns. However, SAF-K8S audit logging infrastructure captures the platform-level events (API calls, model invocations, data access) that form the foundation for these application-level logs.

## SAF-K8S Controls

### [SAF-K8S-1001-007 - Supplemental application-level telemetry for AI workload events](../../controls/SAF-K8S-1001-007.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
