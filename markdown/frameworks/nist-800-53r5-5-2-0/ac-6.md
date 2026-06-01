# NIST SP 800-53 Revision 5 5.2.0 - AC-6

- Framework Code: NIST-800-53R5
- Requirement Title: Least Privilege

## Mapping Notes

Foundational -- agents must operate with minimum necessary permissions

4.1 - Design and enforce RBAC (least-privilege access design); 4.2 - Default SA restrictions, disabling auto-mount of tokens; 1.4 - Control plane configuration file permissions (least-privilege file ownership and modes)

## SAF-K8S Controls

### [SAF-K8S-0104-005 - Control plane configuration file permissions](../../controls/SAF-K8S-0104-005.md)

- Domain: D01 - Control Plane and Cluster Hardening
- Knowledge Area: 1.4
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match

### [SAF-K8S-0401-001 - RBAC least-privilege design](../../controls/SAF-K8S-0401-001.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0401-002 - RBAC permission audit and analysis](../../controls/SAF-K8S-0401-002.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0401-003 - Aggregated ClusterRole governance](../../controls/SAF-K8S-0401-003.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0401-004 - RBAC for AI operator custom resources](../../controls/SAF-K8S-0401-004.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0402-002 - Inactive service account and stale credential remediation](../../controls/SAF-K8S-0402-002.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.2
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0402-003 - Service account identifier exposure prevention](../../controls/SAF-K8S-0402-003.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.2
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0402-004 - Workload identity attribute integrity](../../controls/SAF-K8S-0402-004.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.2
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match

### [SAF-K8S-0402-006 - Cloud workload identity federation for AI services](../../controls/SAF-K8S-0402-006.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.2
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0402-007 - OIDC authentication integration](../../controls/SAF-K8S-0402-007.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.2
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0402-008 - Distinct identity assignment for AI workload types](../../controls/SAF-K8S-0402-008.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.2
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match

### [SAF-K8S-0402-010 - Cross-cluster and cross-cloud cryptographic identity federation](../../controls/SAF-K8S-0402-010.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.2
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match

### [SAF-K8S-0905-038 - Model registry RBAC and workload pull authorization scoping](../../controls/SAF-K8S-0905-038.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0910-016 - Cross-cluster orchestration identity federation and authorization](../../controls/SAF-K8S-0910-016.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0910-022 - Cross-cluster communication authorization policy enforcement](../../controls/SAF-K8S-0910-022.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0910-025 - Cross-cluster registry federation endpoint authorization and reconciliation governance](../../controls/SAF-K8S-0910-025.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
