# EU AI Act 2024/1689 - Article-72.2

- Framework Code: EU-AI-ACT
- Requirement Title: Post-market monitoring by providers and post-market monitoring plan for high-risk AI systems

## Mapping Notes

The post-market monitoring system shall actively and systematically collect, document and analyse relevant data which may be provided by deployers or which may be collected through other sources on the performance of high-risk AI systems throughout their lifetime, and which allow the provider to evaluate the continuous compliance of AI systems with the requirements set out in Chapter III, Section 2. Where relevant, post-market monitoring shall include an analysis of the interaction with other AI systems. This obligation shall not cover sensitive operational data of deployers which are law-enforcement authorities.

SAF-K8S platform controls support systematic data collection through audit logging (D10 KA 10.1), metrics pipelines (D10 KA 10.2), and observability infrastructure (D10 KA 10.5). Data analysis, compliance evaluation, and the full monitoring lifecycle require application-layer and organizational action.

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
