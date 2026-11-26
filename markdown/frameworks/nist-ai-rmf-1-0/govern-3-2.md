# NIST AI Risk Management Framework 1.0 - GOVERN 3.2

- Framework Code: NIST-AI-RMF
- Requirement Title: Policies and procedures are in place to define and differentiate roles and responsibilities for human-AI configurations and oversight of AI systems.

## Mapping Notes

A separate evaluator Job and reviewer ServiceAccount with distinct read/write permissions illustrate separation of the technical paths. Human oversight and assigned responsibilities require independent evidence of the organization's actual roles and procedures.

## SAF-K8S Controls

### [SAF-K8S-0905-045 - Sandboxed external model behavioral vetting and disposition review](../../controls/SAF-K8S-0905-045.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0905-050 - Authenticated reviewer identity validation for model promotion approvals](../../controls/SAF-K8S-0905-050.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0905-057 - External model trust-signal assessment and approval review](../../controls/SAF-K8S-0905-057.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
