# NIST SP 800-53 Revision 5 5.2.0 - AU-2

- Framework Code: NIST-800-53R5
- Requirement Title: Event Logging

## Mapping Notes

The fixture demonstrates policy selection and recording of seven specified API operations under broad and selective policies. It does not define the organization-wide auditable-event catalog or establish coverage of other AI application, runtime, cloud, or provider events.

## SAF-K8S Controls

### [SAF-K8S-1001-004 - Audit volume management for AI workloads](../../controls/SAF-K8S-1001-004.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.1
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-1001-007 - Supplemental application-level telemetry for AI workload events](../../controls/SAF-K8S-1001-007.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.1
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-1001-008 - Permitted responses to audit findings](../../controls/SAF-K8S-1001-008.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
