# NIST SP 800-53 Revision 5 5.2.0 - CM-7

- Framework Code: NIST-800-53R5
- Requirement Title: Least Functionality

## Mapping Notes

Restrict explicit long-lived token Secrets where the organization identifies that credential capability as unnecessary to governed workloads.

## SAF-K8S Controls

### [SAF-K8S-0103-001 - Workload service account token issuance and legacy token restrictions](../../controls/SAF-K8S-0103-001.md)

- Domain: D01 - Control Plane and Cluster Hardening
- Knowledge Area: 1.3
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0103-005 - Pod garbage collection threshold configuration](../../controls/SAF-K8S-0103-005.md)

- Domain: D01 - Control Plane and Cluster Hardening
- Knowledge Area: 1.3
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match

### [SAF-K8S-0103-006 - Profiling endpoint disablement for controller-manager and scheduler](../../controls/SAF-K8S-0103-006.md)

- Domain: D01 - Control Plane and Cluster Hardening
- Knowledge Area: 1.3
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0203-002 - Kernel parameter hardening via sysctl](../../controls/SAF-K8S-0203-002.md)

- Domain: D02 - Node, Runtime, and OS Security
- Knowledge Area: 2.3
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0203-010 - Minimal purpose-built node OS baseline](../../controls/SAF-K8S-0203-010.md)

- Domain: D02 - Node, Runtime, and OS Security
- Knowledge Area: 2.3
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0601-014 - Container image runtime hardening with non-root and read-only filesystem](../../controls/SAF-K8S-0601-014.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
