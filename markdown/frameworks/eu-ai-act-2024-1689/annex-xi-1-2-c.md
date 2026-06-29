# EU AI Act 2024/1689 - Annex-XI.1.2.c

- Framework Code: EU-AI-ACT
- Requirement Title: Technical documentation referred to in Article 53(1), point (a) — technical documentation for providers of general-purpose AI models

## Mapping Notes

information on the data used for training, testing and validation, where applicable, including the type and provenance of data and curation methodologies (e.g. cleaning, filtering, etc.), the number of data points, their scope and main characteristics; how the data was obtained and selected as well as all other measures to detect the unsuitability of data sources and methods to detect identifiable biases, where applicable;

SAF-K8S GPU tracking (D8), resource quota management, and training pipeline telemetry (D9/D10) directly capture compute resources, training data volumes, and total FLOPS consumed during training on Kubernetes infrastructure.

## SAF-K8S Controls

### [SAF-K8S-0801-001 - GPU device plugin security configuration and hardening](../../controls/SAF-K8S-0801-001.md)

- Domain: D08 - GPU, Accelerator, and Confidential Computing
- Knowledge Area: 8.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0805-001 - GPU telemetry collection and anomaly detection](../../controls/SAF-K8S-0805-001.md)

- Domain: D08 - GPU, Accelerator, and Confidential Computing
- Knowledge Area: 8.5
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0805-002 - GPU allocation audit trail and workload identity tracking](../../controls/SAF-K8S-0805-002.md)

- Domain: D08 - GPU, Accelerator, and Confidential Computing
- Knowledge Area: 8.5
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0904-001 - Pipeline orchestrator hardening](../../controls/SAF-K8S-0904-001.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.4
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0906-002 - Large-scale data integrity verification](../../controls/SAF-K8S-0906-002.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.6
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
