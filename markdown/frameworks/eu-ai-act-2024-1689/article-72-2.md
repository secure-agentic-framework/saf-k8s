# EU AI Act 2024/1689 - Article-72.2

- Framework Code: EU-AI-ACT
- Requirement Title: Post-market monitoring by providers and post-market monitoring plan for high-risk AI systems

## Mapping Notes

This tracing control may contribute a source of interaction and operational data to post-market monitoring only when deployed traces are actively and systematically collected, documented, retained as required, and analyzed by the provider against named performance and continuous-compliance criteria throughout the system lifecycle. The reference proves synthetic trace propagation and span parentage, not systematic production collection, analysis, lifetime coverage, or compliance evaluation.

## SAF-K8S Controls

### [SAF-K8S-1002-002 - Distributed tracing for ML pipelines](../../controls/SAF-K8S-1002-002.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.2
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-1002-003 - AI workload telemetry integration into cluster monitoring](../../controls/SAF-K8S-1002-003.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.2
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
