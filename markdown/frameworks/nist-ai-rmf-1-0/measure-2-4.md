# NIST AI Risk Management Framework 1.0 - MEASURE 2.4

- Framework Code: NIST-AI-RMF
- Requirement Title: The functionality and behavior of the AI system and its components - as identified in the MAP function - are monitored when in production.

## Mapping Notes

SAF-K8S mandates comprehensive production monitoring: audit policies capture AI-relevant CRD operations, SIEM integration detects AI-specific attack patterns, metrics endpoints monitor model performance, and distributed tracing tracks pipeline execution.

## SAF-K8S Controls

### [SAF-K8S-0101-005 - Streaming connection idle timeout enforcement](../../controls/SAF-K8S-0101-005.md)

- Domain: D01 - Control Plane and Cluster Hardening
- Knowledge Area: 1.1
- Relation Type: supports
- Strength: weak
- Applicability: required
- Strength Reason Code: semantic-mismatch-candidate

### [SAF-K8S-1001-016 - Audit policy coverage for AI-specific resource and workflow events](../../controls/SAF-K8S-1001-016.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.1
- Relation Type: supports
- Strength: moderate
- Applicability: required
- Strength Reason Code: depends-on-adjacent-control

### [SAF-K8S-1002-001 - Metric endpoint authentication](../../controls/SAF-K8S-1002-001.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.2
- Relation Type: supports
- Strength: weak
- Applicability: required
- Strength Reason Code: implementation-specific

### [SAF-K8S-1002-002 - Distributed tracing for ML pipelines](../../controls/SAF-K8S-1002-002.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.2
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: partial-coverage

### [SAF-K8S-0910-032 - Cross-cluster traffic anomaly monitoring for distributed AI workloads](../../controls/SAF-K8S-0910-032.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
