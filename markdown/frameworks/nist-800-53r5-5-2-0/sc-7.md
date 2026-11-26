# NIST SP 800-53 Revision 5 5.2.0 - SC-7

- Framework Code: NIST-800-53R5
- Requirement Title: Boundary Protection

## Mapping Notes

The case demonstrates one internal workload boundary enforced by NetworkPolicy. It does not test external managed interfaces, node or hostNetwork traffic, or production network boundaries.

## SAF-K8S Controls

### [SAF-K8S-0501-001 - Default deny ingress and egress network policies](../../controls/SAF-K8S-0501-001.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.1
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0501-002 - Namespace network isolation patterns](../../controls/SAF-K8S-0501-002.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0501-003 - Workload egress controls](../../controls/SAF-K8S-0501-003.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0501-004 - CNI-specific network policy extensions](../../controls/SAF-K8S-0501-004.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.1
- Relation Type: supports
- Strength: moderate
- Applicability: required
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0501-006 - Multi-cluster network segmentation for federated AI workloads](../../controls/SAF-K8S-0501-006.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0501-007 - East-west AI workload traffic monitoring](../../controls/SAF-K8S-0501-007.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0501-008 - AI workload type network microsegmentation](../../controls/SAF-K8S-0501-008.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
