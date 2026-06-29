# EU AI Act 2024/1689 - Article-15.1

- Framework Code: EU-AI-ACT
- Requirement Title: Accuracy, robustness and cybersecurity

## Mapping Notes

High-risk AI systems shall be designed and developed in such a way that they achieve an appropriate level of accuracy, robustness, and cybersecurity, and that they perform consistently in those respects throughout their lifecycle.

SAF-K8S directly supports robustness and cybersecurity through workload isolation, runtime security, supply chain integrity, and continuous monitoring. However, accuracy is fundamentally an application-layer and model concern -- SAF-K8S has no controls that directly govern model accuracy levels.

## SAF-K8S Controls

### [SAF-K8S-0204-001 - Runtime security tool deployment for syscall and network monitoring](../../controls/SAF-K8S-0204-001.md)

- Domain: D02 - Node, Runtime, and OS Security
- Knowledge Area: 2.4
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0301-001 - Pod Security Standards level assignment](../../controls/SAF-K8S-0301-001.md)

- Domain: D03 - Workload and Pod Security
- Knowledge Area: 3.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation

### [SAF-K8S-0604-001 - SBOM generation for container and AI artifacts](../../controls/SAF-K8S-0604-001.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.4
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
