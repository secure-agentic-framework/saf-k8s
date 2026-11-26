# NIST AI Risk Management Framework 1.0 - GOVERN 1.7

- Framework Code: NIST-AI-RMF
- Requirement Title: Processes and procedures are in place for decommissioning and phasing out AI systems safely and in a manner that does not increase risks or harms.

## Mapping Notes

This fixture demonstrates one bounded technical contribution: it records a synthetic deletion notice across a fixed source-to-dependent graph and observes logical removal of selected Kubernetes API objects after releasing a Pod reference. It does not establish safe decommissioning procedures, impact/harm assessment, removal of secrets, grants, reservations or data bytes, or organization-wide phasing out of AI systems. Verify the actual adopted workflow and retained copies separately.

## SAF-K8S Controls

### [SAF-K8S-0905-006 - Model artifact lifecycle management](../../controls/SAF-K8S-0905-006.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-1007-005 - Change management for production AI model deployments](../../controls/SAF-K8S-1007-005.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.7
- Relation Type: supports
- Strength: moderate
- Applicability: required
- Strength Reason Code: depends-on-adjacent-control
