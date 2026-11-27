# NIST SP 800-53 Revision 5 5.2.0 - IA-4

- Framework Code: NIST-800-53R5
- Requirement Title: Identifier Management

## Mapping Notes

Governed workload identifier assignment and approved provider identity binding are independently verified.

## SAF-K8S Controls

### [SAF-K8S-0402-006 - Cloud workload identity federation for AI services](../../controls/SAF-K8S-0402-006.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.2
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: n/a

### [SAF-K8S-0402-007 - OIDC authentication integration](../../controls/SAF-K8S-0402-007.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.2
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: n/a

### [SAF-K8S-0402-010 - Cross-cluster and cross-cloud cryptographic identity federation](../../controls/SAF-K8S-0402-010.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.2
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match

### [SAF-K8S-0901-002 - Parameter server and all-reduce security](../../controls/SAF-K8S-0901-002.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.1
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0901-005 - Federated learning security on Kubernetes](../../controls/SAF-K8S-0901-005.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.1
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0901-006 - Gang scheduling security (Volcano, Kueue)](../../controls/SAF-K8S-0901-006.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.1
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0901-007 - AI operator privilege management](../../controls/SAF-K8S-0901-007.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.1
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
