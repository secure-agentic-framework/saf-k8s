# EU AI Act 2024/1689 - Article-12.1

- Framework Code: EU-AI-ACT
- Requirement Title: Record-keeping

## Mapping Notes

High-risk AI systems shall technically allow for the automatic recording of events (logs) over the lifetime of the system.

SAF-K8S audit logging controls (D10) provide comprehensive logging infrastructure including Kubernetes audit logs, workload logs, GPU utilization logs, and AI pipeline execution logs with structured formats.

## SAF-K8S Controls

### [SAF-K8S-0805-002 - GPU allocation audit trail and workload identity tracking](../../controls/SAF-K8S-0805-002.md)

- Domain: D08 - GPU, Accelerator, and Confidential Computing
- Knowledge Area: 8.5
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-1001-004 - Audit volume management for AI workloads](../../controls/SAF-K8S-1001-004.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-1001-007 - Supplemental application-level telemetry for AI workload events](../../controls/SAF-K8S-1001-007.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation
