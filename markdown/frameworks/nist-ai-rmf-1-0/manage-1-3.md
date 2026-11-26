# NIST AI Risk Management Framework 1.0 - MANAGE 1.3

- Framework Code: NIST-AI-RMF
- Requirement Title: Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.

## Mapping Notes

The workflow contributes a documented technical response and review. Verify the applicable AI risk, selected response option and responsible owner.

## SAF-K8S Controls

### [SAF-K8S-1005-001 - Kubernetes incident response lifecycle](../../controls/SAF-K8S-1005-001.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.5
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-1005-008 - AI-specific incident response playbooks for Kubernetes](../../controls/SAF-K8S-1005-008.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.5
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0910-033 - Investigation of anomalous cross-cluster AI communication](../../controls/SAF-K8S-0910-033.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
