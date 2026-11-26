# NIST SP 800-53 Revision 5 5.2.0 - PS-5

- Framework Code: NIST-800-53R5
- Requirement Title: Personnel Transfer

## Mapping Notes

Periodic RBAC review can support the access-update portion of PS-5 when the organization links personnel transfer events to affected identities, reviews assigned permissions, and records resulting updates. The fixture demonstrates only synthetic grant review and reconciliation; it does not implement personnel transfer notification or offboarding.

## SAF-K8S Controls

### [SAF-K8S-0401-002 - RBAC permission audit and analysis](../../controls/SAF-K8S-0401-002.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.1
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
