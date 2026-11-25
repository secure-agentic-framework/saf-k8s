# NIST SP 800-53 Revision 5 5.2.0 - CM-6

- Framework Code: NIST-800-53R5
- Requirement Title: Configuration Settings

## Mapping Notes

Record approved configuration settings, applied values and authorized deviations. For this token control, evidence includes configured TokenRequest scope, workload projection, and admission of explicit legacy token Secrets.

## SAF-K8S Controls

### [SAF-K8S-0103-001 - Workload service account token issuance and legacy token restrictions](../../controls/SAF-K8S-0103-001.md)

- Domain: D01 - Control Plane and Cluster Hardening
- Knowledge Area: 1.3
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0103-005 - Pod garbage collection threshold configuration](../../controls/SAF-K8S-0103-005.md)

- Domain: D01 - Control Plane and Cluster Hardening
- Knowledge Area: 1.3
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0103-006 - Profiling endpoint disablement for controller-manager and scheduler](../../controls/SAF-K8S-0103-006.md)

- Domain: D01 - Control Plane and Cluster Hardening
- Knowledge Area: 1.3
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0104-005 - Control plane configuration file permissions](../../controls/SAF-K8S-0104-005.md)

- Domain: D01 - Control Plane and Cluster Hardening
- Knowledge Area: 1.4
- Relation Type: supports
- Strength: moderate
- Applicability: required
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0201-005 - Kubelet hostname override governance](../../controls/SAF-K8S-0201-005.md)

- Domain: D02 - Node, Runtime, and OS Security
- Knowledge Area: 2.1
- Relation Type: supports
- Strength: moderate
- Applicability: required
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0201-008 - Kubelet configuration and credential file ownership and permissions](../../controls/SAF-K8S-0201-008.md)

- Domain: D02 - Node, Runtime, and OS Security
- Knowledge Area: 2.1
- Relation Type: supports
- Strength: moderate
- Applicability: required
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0201-014 - Kubelet serving certificate trust and expiry enforcement](../../controls/SAF-K8S-0201-014.md)

- Domain: D02 - Node, Runtime, and OS Security
- Knowledge Area: 2.1
- Relation Type: supports
- Strength: moderate
- Applicability: required
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0606-020 - Helm values override restriction and dependency integrity governance](../../controls/SAF-K8S-0606-020.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.6
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0910-018 - Security-aware target-cluster posture verification before multi-cluster placement](../../controls/SAF-K8S-0910-018.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0910-026 - Multi-cluster security policy baseline federation](../../controls/SAF-K8S-0910-026.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
