# EU AI Act 2024/1689 - Annex-XI.1.2.d

- Framework Code: EU-AI-ACT
- Requirement Title: Technical documentation referred to in Article 53(1), point (a) — technical documentation for providers of general-purpose AI models

## Mapping Notes

the computational resources used to train the model (e.g. number of floating point operations), training time, and other relevant details related to the training;

SAF-K8S GPU resource tracking (D8), Kubernetes resource quota management, job scheduling records, and training pipeline telemetry (D9/D10) directly capture computational resource usage, training duration, and infrastructure configuration.

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

### [SAF-K8S-0901-006 - Gang scheduling security (Volcano, Kueue)](../../controls/SAF-K8S-0901-006.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
