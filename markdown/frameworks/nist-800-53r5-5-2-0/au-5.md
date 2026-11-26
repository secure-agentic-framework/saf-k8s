# NIST SP 800-53 Revision 5 5.2.0 - AU-5

- Framework Code: NIST-800-53R5
- Requirement Title: Response to Audit Logging Process Failures

## Mapping Notes

The webhook fixture observes one transient 503, one retry of the same audit event, delivery counts, and native counter deltas. It does not alert personnel or test a production failure-response process.

## SAF-K8S Controls

### [SAF-K8S-1001-004 - Audit volume management for AI workloads](../../controls/SAF-K8S-1001-004.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.1
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-1001-008 - Permitted responses to audit findings](../../controls/SAF-K8S-1001-008.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.1
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
