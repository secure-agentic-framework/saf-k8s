# NIST SP 800-53 Revision 5 5.2.0 - IA-3

- Framework Code: NIST-800-53R5
- Requirement Title: Device Identification and Authentication

## Mapping Notes

Authenticated enrollment bound to an intended registered Node supports device identification and authentication for the scoped nodes.

## SAF-K8S Controls

### [SAF-K8S-0201-005 - Kubelet hostname override governance](../../controls/SAF-K8S-0201-005.md)

- Domain: D02 - Node, Runtime, and OS Security
- Knowledge Area: 2.1
- Relation Type: supports
- Strength: moderate
- Applicability: required
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0201-013 - Kubelet client certificate rotation via TLS bootstrap](../../controls/SAF-K8S-0201-013.md)

- Domain: D02 - Node, Runtime, and OS Security
- Knowledge Area: 2.1
- Relation Type: supports
- Strength: moderate
- Applicability: required
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0804-001 - TEE-based model and data protection for AI workloads](../../controls/SAF-K8S-0804-001.md)

- Domain: D08 - GPU, Accelerator, and Confidential Computing
- Knowledge Area: 8.4
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0804-002 - Remote attestation for TEE integrity verification](../../controls/SAF-K8S-0804-002.md)

- Domain: D08 - GPU, Accelerator, and Confidential Computing
- Knowledge Area: 8.4
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0910-021 - Cross-cluster endpoint and workload authentication for AI communication](../../controls/SAF-K8S-0910-021.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: n/a
