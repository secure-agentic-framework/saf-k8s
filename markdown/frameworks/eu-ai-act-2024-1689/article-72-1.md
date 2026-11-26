# EU AI Act 2024/1689 - Article-72.1

- Framework Code: EU-AI-ACT
- Requirement Title: Post-market monitoring by providers and post-market monitoring plan for high-risk AI systems

## Mapping Notes

Providers shall establish and document a post-market monitoring system in a manner that is proportionate to the nature of the AI technologies and the risks of the high-risk AI system.

SAF-K8S observability controls (D10) provide the monitoring infrastructure that is a critical component of any post-market monitoring system on Kubernetes: telemetry collection, anomaly detection, alerting, and audit logging. The system design, documentation, and organizational processes are out of scope.

## SAF-K8S Controls

### [SAF-K8S-1002-002 - Distributed tracing for ML pipelines](../../controls/SAF-K8S-1002-002.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.2
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
