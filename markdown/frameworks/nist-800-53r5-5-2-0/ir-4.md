# NIST SP 800-53 Revision 5 5.2.0 - IR-4

- Framework Code: NIST-800-53R5
- Requirement Title: Incident Handling

## Mapping Notes

The fixture contributes to the containment portion of IR-4: a scoped responder captures synthetic workload state and application logs before halting one workload, and an investigator verifies the retained record after Pod removal. The added server-side dry-run confirms Kubernetes rejects a change to the immutable fixture record and that its digest and bytes remain unchanged. The case does not establish an end-to-end incident handling capability, the organization's incident response plan, cross-organization consistency, production response objectives, or recovery.

## SAF-K8S Controls

### [SAF-K8S-0905-037 - Manual emergency halt governance and forensic evidence preservation](../../controls/SAF-K8S-0905-037.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: partial
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0910-019 - Compromised-cluster federation isolation and re-admission governance](../../controls/SAF-K8S-0910-019.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: n/a

### [SAF-K8S-0910-029 - Centralized multi-cluster secret, certificate, and incident governance coordination](../../controls/SAF-K8S-0910-029.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: n/a

### [SAF-K8S-0910-033 - Investigation of anomalous cross-cluster AI communication](../../controls/SAF-K8S-0910-033.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-1005-001 - Kubernetes incident response lifecycle](../../controls/SAF-K8S-1005-001.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.5
- Relation Type: direct
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
