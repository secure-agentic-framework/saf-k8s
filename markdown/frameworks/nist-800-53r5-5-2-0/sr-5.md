# NIST SP 800-53 Revision 5 5.2.0 - SR-5

- Framework Code: NIST-800-53R5
- Requirement Title: Acquisition Strategies, Tools, and Methods

## Mapping Notes

Acquisition strategies for AI components must address unique supply chain security needs

8.1 - Device plugin framework (GPU acquisition/provisioning); 6.1 - Base image selection (image acquisition strategy)

## SAF-K8S Controls

### [SAF-K8S-0601-007 - AI GPU and ML framework base image validation](../../controls/SAF-K8S-0601-007.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.1
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match

### [SAF-K8S-0601-015 - Inference image minimal composition with GPU runtime-only dependencies](../../controls/SAF-K8S-0601-015.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.1
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0801-001 - GPU device plugin security configuration and hardening](../../controls/SAF-K8S-0801-001.md)

- Domain: D08 - GPU, Accelerator, and Confidential Computing
- Knowledge Area: 8.1
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0801-002 - MIG partitioning for hardware-enforced GPU isolation](../../controls/SAF-K8S-0801-002.md)

- Domain: D08 - GPU, Accelerator, and Confidential Computing
- Knowledge Area: 8.1
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0801-004 - vGPU virtualization security controls](../../controls/SAF-K8S-0801-004.md)

- Domain: D08 - GPU, Accelerator, and Confidential Computing
- Knowledge Area: 8.1
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0801-006 - GPU memory clearing between workload transitions](../../controls/SAF-K8S-0801-006.md)

- Domain: D08 - GPU, Accelerator, and Confidential Computing
- Knowledge Area: 8.1
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
