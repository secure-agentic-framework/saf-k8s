# NIST AI Risk Management Framework 1.0 - MEASURE 1.2

- Framework Code: NIST-AI-RMF
- Requirement Title: Appropriateness of AI metrics and effectiveness of existing measures are regularly assessed and updated, including measures of accuracy, fairness and bias, data quality, security, explainability, and privacy.

## Mapping Notes

Metrics endpoint security ensures telemetry integrity and availability. GPU telemetry collection supports hardware-level measurement validation. Security posture management drives continuous metric reassessment.

## SAF-K8S Controls

### [SAF-K8S-0805-001 - GPU telemetry collection and anomaly detection](../../controls/SAF-K8S-0805-001.md)

- Domain: D08 - GPU, Accelerator, and Confidential Computing
- Knowledge Area: 8.5
- Relation Type: partial
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match

### [SAF-K8S-1002-001 - Metric endpoint authentication](../../controls/SAF-K8S-1002-001.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.2
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-1007-004 - Continuous security posture management for AI clusters](../../controls/SAF-K8S-1007-004.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.7
- Relation Type: partial
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match
