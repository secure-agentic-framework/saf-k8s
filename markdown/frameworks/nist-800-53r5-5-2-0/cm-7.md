# NIST SP 800-53 Revision 5 5.2.0 - CM-7

- Framework Code: NIST-800-53R5
- Requirement Title: Least Functionality

## Mapping Notes

Agents should expose minimum necessary functionality

6.1 - Secure container images (distroless, scratch, minimal attack surface); 2.3 - Minimal host OS; 1.3 - Profiling endpoint disablement for controller-manager and scheduler (--profiling=false)

## SAF-K8S Controls

### [SAF-K8S-0103-001 - Controller-manager service account token hardening](../../controls/SAF-K8S-0103-001.md)

- Domain: D01 - Control Plane and Cluster Hardening
- Knowledge Area: 1.3
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

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
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0203-004 - Secure boot and verified boot chain enforcement](../../controls/SAF-K8S-0203-004.md)

- Domain: D02 - Node, Runtime, and OS Security
- Knowledge Area: 2.3
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0601-014 - Container image runtime hardening with non-root and read-only filesystem](../../controls/SAF-K8S-0601-014.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
