# EU AI Act 2024/1689 - Annex-IV:IV(8)

- Framework Code: EU-AI-ACT
- Requirement Title: Technical Documentation Referred to in Article 11(1)

## Mapping Notes

A description of the system in place to evaluate the AI system performance in the post-market phase in accordance with Article 72, including the post-market monitoring plan referred to in Article 72(3).

SAF-K8S observability and incident response controls (D10) provide the monitoring infrastructure backbone: telemetry collection, anomaly detection, alerting pipelines. However, the complete post-market monitoring system design, including what metrics to track, what thresholds constitute degradation, and how to evaluate ongoing compliance, requires organizational and application-layer decisions.

## SAF-K8S Controls

### [SAF-K8S-0805-001 - GPU telemetry collection and anomaly detection](../../controls/SAF-K8S-0805-001.md)

- Domain: D08 - GPU, Accelerator, and Confidential Computing
- Knowledge Area: 8.5
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation

### [SAF-K8S-1002-002 - Distributed tracing for ML pipelines](../../controls/SAF-K8S-1002-002.md)

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
- Strength Reason Code: framework-language-interpretation
