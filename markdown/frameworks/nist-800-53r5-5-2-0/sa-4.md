# NIST SP 800-53 Revision 5 5.2.0 - SA-4

- Framework Code: NIST-800-53R5
- Requirement Title: Acquisition Process

## Mapping Notes

Acquisition of agentic AI components (models, tools, plugins) requires security requirements

8.2 - GPU driver/library security (acquisition controls); 9.4 - ML dependency management and acquisition

## SAF-K8S Controls

### [SAF-K8S-0802-001 - GPU driver lifecycle and vulnerability management](../../controls/SAF-K8S-0802-001.md)

- Domain: D08 - GPU, Accelerator, and Confidential Computing
- Knowledge Area: 8.2
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0802-002 - CUDA library and container toolkit security](../../controls/SAF-K8S-0802-002.md)

- Domain: D08 - GPU, Accelerator, and Confidential Computing
- Knowledge Area: 8.2
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0802-004 - GPU firmware integrity monitoring](../../controls/SAF-K8S-0802-004.md)

- Domain: D08 - GPU, Accelerator, and Confidential Computing
- Knowledge Area: 8.2
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0904-001 - Pipeline orchestrator hardening](../../controls/SAF-K8S-0904-001.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.4
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0904-003 - Notebook and experimentation environment security](../../controls/SAF-K8S-0904-003.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.4
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
