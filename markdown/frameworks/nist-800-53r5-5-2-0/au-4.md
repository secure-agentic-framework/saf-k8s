# NIST SP 800-53 Revision 5 5.2.0 - AU-4

- Framework Code: NIST-800-53R5
- Requirement Title: Audit Log Storage Capacity

## Mapping Notes

The case measures raw audit bytes for five repeated polls under two policy levels and reports rotation flags. This is a bounded sizing input only; it does not demonstrate required capacity, retention duration, peak rate, or capacity margin.

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
