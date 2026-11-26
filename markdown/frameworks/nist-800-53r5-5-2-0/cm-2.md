# NIST SP 800-53 Revision 5 5.2.0 - CM-2

- Framework Code: NIST-800-53R5
- Requirement Title: Baseline Configuration

## Mapping Notes

The approved ownership and mode requirements contribute a scoped part of the system configuration baseline.

## SAF-K8S Controls

### [SAF-K8S-0104-005 - Control plane configuration file permissions](../../controls/SAF-K8S-0104-005.md)

- Domain: D01 - Control Plane and Cluster Hardening
- Knowledge Area: 1.4
- Relation Type: supports
- Strength: moderate
- Applicability: required
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0302-001 - Pod and container security context enforcement](../../controls/SAF-K8S-0302-001.md)

- Domain: D03 - Workload and Pod Security
- Knowledge Area: 3.2
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0910-026 - Multi-cluster security policy baseline federation](../../controls/SAF-K8S-0910-026.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
