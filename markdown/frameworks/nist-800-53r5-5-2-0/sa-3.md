# NIST SP 800-53 Revision 5 5.2.0 - SA-3

- Framework Code: NIST-800-53R5
- Requirement Title: System Development Life Cycle

## Mapping Notes

For a selected governed Kubernetes delivery path, enforce and retain decisions at the defined Develop, Distribute, and Deploy checkpoints for the same artifact; assess Runtime separately. This is partial implementation evidence for lifecycle security checkpoints and does not establish the full SA-3 system development life cycle, roles, responsibilities, or risk-management integration.

## SAF-K8S Controls

### [SAF-K8S-0606-017 - CNCF lifecycle phase security coverage](../../controls/SAF-K8S-0606-017.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.6
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-1004-001 - ML threat taxonomy per CTA-2114 mapped to Kubernetes](../../controls/SAF-K8S-1004-001.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.4
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-1004-002 - Software supply chain threat model per NIST SP 800-204D](../../controls/SAF-K8S-1004-002.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.4
- Relation Type: partial
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
