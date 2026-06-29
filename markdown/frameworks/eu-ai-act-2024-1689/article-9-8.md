# EU AI Act 2024/1689 - Article-9.8

- Framework Code: EU-AI-ACT
- Requirement Title: Risk management system

## Mapping Notes

The testing of high-risk AI systems shall be performed, as appropriate, at any time throughout the development process, and, in any event, prior to their being placed on the market or put into service. Testing shall be carried out against prior defined metrics and probabilistic thresholds that are appropriate to the intended purpose of the high-risk AI system.

SAF-K8S model promotion gates (SAF-K8S-0905-005) and CI pipeline security gates (SAF-K8S-0606-003) enforce testing requirements before deployment. Defining metrics and thresholds is an application-layer concern.

## SAF-K8S Controls

### [SAF-K8S-0606-011 - CI build-time security gate enforcement](../../controls/SAF-K8S-0606-011.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.6
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0905-005 - Automated model promotion gates](../../controls/SAF-K8S-0905-005.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0905-012 - Development-to-production environment separation for AI workloads](../../controls/SAF-K8S-0905-012.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
