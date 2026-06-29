# EU AI Act 2024/1689 - Article-72.1

- Framework Code: EU-AI-ACT
- Requirement Title: Post-market monitoring by providers and post-market monitoring plan for high-risk AI systems

## Mapping Notes

Providers shall establish and document a post-market monitoring system in a manner that is proportionate to the nature of the AI technologies and the risks of the high-risk AI system.

SAF-K8S deployment controls can enforce pre-deployment checklists through admission webhooks, requiring that monitoring and observability configurations are present before workloads are admitted. The organizational documentation obligation is outside infrastructure scope.

## SAF-K8S Controls

### [SAF-K8S-0605-001 - OPA/Gatekeeper policies for Kubernetes and AI workloads](../../controls/SAF-K8S-0605-001.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.5
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

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
