# NIST SP 800-53 Revision 5 5.2.0 - AC-2

- Framework Code: NIST-800-53R5
- Requirement Title: Account Management

## Mapping Notes

This control supports the inactivity, monitoring and retirement portions of account management. Verify the remaining organization-defined account lifecycle requirements separately.

## SAF-K8S Controls

### [SAF-K8S-0402-002 - Inactive service account and stale credential remediation](../../controls/SAF-K8S-0402-002.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.2
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0402-007 - OIDC authentication integration](../../controls/SAF-K8S-0402-007.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.2
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: n/a

### [SAF-K8S-0402-008 - Distinct identity assignment for AI workload types](../../controls/SAF-K8S-0402-008.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.2
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0402-010 - Cross-cluster and cross-cloud cryptographic identity federation](../../controls/SAF-K8S-0402-010.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.2
- Relation Type: supports
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation

### [SAF-K8S-0905-039 - Model registry access review and stale-permission remediation](../../controls/SAF-K8S-0905-039.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: partial
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0910-031 - Cross-cluster registry endpoint enrollment approval](../../controls/SAF-K8S-0910-031.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
