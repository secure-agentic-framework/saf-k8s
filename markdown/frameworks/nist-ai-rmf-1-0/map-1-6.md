# NIST AI Risk Management Framework 1.0 - MAP 1.6

- Framework Code: NIST-AI-RMF
- Requirement Title: System requirements (e.g., "the system shall respect the privacy of its users") are elicited from and understood by relevant AI actors. Design decisions take socio-technical implications into account to address AI risks.

## Mapping Notes

AI system classification captures security requirements per system type. Training data privacy controls and differential privacy mechanisms enforce privacy requirements at the infrastructure level.

## SAF-K8S Controls

### [SAF-K8S-0905-001 - AI system lifecycle classification](../../controls/SAF-K8S-0905-001.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0907-002 - Training data privacy controls](../../controls/SAF-K8S-0907-002.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.7
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: partial-control-coverage
