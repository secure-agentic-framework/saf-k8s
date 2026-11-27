# NIST SP 800-53 Revision 5 5.2.0 - CM-8

- Framework Code: NIST-800-53R5
- Requirement Title: System Component Inventory

## Mapping Notes

Can contribute origin, immutable digest, internalization event and registry-location fields for an in-scope model artifact. It does not inventory all system components or establish organization-wide inventory completeness or update cadence.

## SAF-K8S Controls

### [SAF-K8S-0905-059 - External-origin annotation and internal registry enrollment for approved external models](../../controls/SAF-K8S-0905-059.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-1007-004 - Continuous security posture management for AI clusters](../../controls/SAF-K8S-1007-004.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.7
- Relation Type: partial
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-1007-006 - Secure AI workload decommissioning](../../controls/SAF-K8S-1007-006.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.7
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
