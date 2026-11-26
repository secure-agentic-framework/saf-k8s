# NIST SP 800-53 Revision 5 5.2.0 - IA-5

- Framework Code: NIST-800-53R5
- Requirement Title: Authenticator Management

## Mapping Notes

Governed external authenticator storage, distribution and scoped recipient identity are independently verified.

## SAF-K8S Controls

### [SAF-K8S-0403-002 - External secrets management integration](../../controls/SAF-K8S-0403-002.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.3
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: n/a

### [SAF-K8S-0403-004 - Secret rotation and expiration enforcement](../../controls/SAF-K8S-0403-004.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.3
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: n/a

### [SAF-K8S-0403-005 - AI pipeline secret leakage prevention](../../controls/SAF-K8S-0403-005.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.3
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0403-006 - Per-workload credential scoping for AI jobs](../../controls/SAF-K8S-0403-006.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.3
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: n/a

### [SAF-K8S-0402-002 - Inactive service account and stale credential remediation](../../controls/SAF-K8S-0402-002.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.2
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
