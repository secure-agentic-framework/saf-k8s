# NIST SP 800-53 Revision 5 5.2.0 - CM-5

- Framework Code: NIST-800-53R5
- Requirement Title: Access Restrictions for Change

## Mapping Notes

Restrictive modes and ownership limit filesystem changes to these artifacts. Record the separate procedures governing authorization and change approval.

## SAF-K8S Controls

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

### [SAF-K8S-0606-024 - Policy-as-code and runtime configuration integrity governance](../../controls/SAF-K8S-0606-024.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.6
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0904-001 - Pipeline orchestrator hardening](../../controls/SAF-K8S-0904-001.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.4
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
