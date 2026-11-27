# NIST AI Risk Management Framework 1.0 - MAP 4.2

- Framework Code: NIST-AI-RMF
- Requirement Title: Internal risk controls for components of the AI system, including third-party AI technologies, are identified and documented.

## Mapping Notes

The implemented and verified dataset integrity control is identified in the AI system risk documentation.

## SAF-K8S Controls

### [SAF-K8S-0906-002 - Segmented dataset integrity verification](../../controls/SAF-K8S-0906-002.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.6
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: n/a

### [SAF-K8S-1006-004 - Automated audit readiness for Kubernetes AI platforms](../../controls/SAF-K8S-1006-004.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.6
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
