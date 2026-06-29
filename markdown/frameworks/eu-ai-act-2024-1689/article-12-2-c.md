# EU AI Act 2024/1689 - Article-12.2.c

- Framework Code: EU-AI-ACT
- Requirement Title: Record-keeping

## Mapping Notes

monitoring the operation of high-risk AI systems referred to in Article 26(5).

SAF-K8S provides operational monitoring infrastructure through cluster monitoring, workload telemetry, and SIEM integration. Full operational monitoring of AI systems also requires application-layer event generation for AI-specific operational events (input/output logging, decision auditing).

## SAF-K8S Controls

### [SAF-K8S-1001-028 - AI-specific SIEM source onboarding and forwarding](../../controls/SAF-K8S-1001-028.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-1002-003 - AI workload telemetry integration into cluster monitoring](../../controls/SAF-K8S-1002-003.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.2
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
