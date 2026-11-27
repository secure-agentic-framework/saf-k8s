# NIST SP 800-53 Revision 5 5.2.0 - SC-8

- Framework Code: NIST-800-53R5
- Requirement Title: Transmission Confidentiality and Integrity

## Mapping Notes

The CNI-selection procedure can support transmission confidentiality when it requires and verifies the selected plugin encryption capability. Separate case SAF-K8S-0502-002 demonstrates Cilium 1.20.5 WireGuard on one cross-node path; SAF-K8S-0502-001 itself does not enable or test encryption. Same-node, host, other route, and other CNI coverage remain unverified.

## SAF-K8S Controls

### [SAF-K8S-0502-001 - CNI plugin security selection criteria](../../controls/SAF-K8S-0502-001.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.2
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0502-002 - Pod-to-pod traffic encryption](../../controls/SAF-K8S-0502-002.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.2
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0502-005 - AI workload data path encryption in transit](../../controls/SAF-K8S-0502-005.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.2
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0504-001 - Zero trust networking principles for Kubernetes](../../controls/SAF-K8S-0504-001.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.4
- Relation Type: supports
- Strength: moderate
- Applicability: required
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0504-002 - Service mesh mTLS and authorization policies](../../controls/SAF-K8S-0504-002.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.4
- Relation Type: supports
- Strength: moderate
- Applicability: required
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0910-004 - Federated learning cross-cluster coordination security](../../controls/SAF-K8S-0910-004.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0910-020 - Cross-cluster transport encryption for distributed AI traffic](../../controls/SAF-K8S-0910-020.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: n/a

### [SAF-K8S-0910-030 - Cross-cluster registry replication channel mutual authentication](../../controls/SAF-K8S-0910-030.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0501-006 - Multi-cluster network segmentation for federated AI workloads](../../controls/SAF-K8S-0501-006.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.1
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0902-004 - Multi-model serving isolation and encryption](../../controls/SAF-K8S-0902-004.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.2
- Relation Type: partial
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0902-005 - Multi-cluster inference routing and failover security](../../controls/SAF-K8S-0902-005.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.2
- Relation Type: partial
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
