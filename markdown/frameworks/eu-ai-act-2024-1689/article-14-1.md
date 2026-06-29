# EU AI Act 2024/1689 - Article-14.1

- Framework Code: EU-AI-ACT
- Requirement Title: Human oversight

## Mapping Notes

High-risk AI systems shall be designed and developed in such a way, including with appropriate human-machine interface tools, that they can be effectively overseen by natural persons during the period in which they are in use.

SAF-K8S provides infrastructure for human oversight through policy controllers (admission control), deployment approval gates (SAF-K8S-0905-010), and observability (D10). The design of human-machine interface tools is an application-layer concern.

## SAF-K8S Controls

### [SAF-K8S-0605-001 - OPA/Gatekeeper policies for Kubernetes and AI workloads](../../controls/SAF-K8S-0605-001.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.5
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-1002-003 - AI workload telemetry integration into cluster monitoring](../../controls/SAF-K8S-1002-003.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.2
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
