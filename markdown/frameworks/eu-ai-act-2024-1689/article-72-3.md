# EU AI Act 2024/1689 - Article-72.3

- Framework Code: EU-AI-ACT
- Requirement Title: Post-market monitoring by providers and post-market monitoring plan for high-risk AI systems

## Mapping Notes

The post-market monitoring system shall be based on a post-market monitoring plan. The post-market monitoring plan shall be part of the technical documentation referred to in Annex IV. The Commission shall adopt an implementing act laying down detailed provisions establishing a template for the post-market monitoring plan and the list of elements to be included in the plan by 2 February 2026. That implementing act shall be adopted in accordance with the examination procedure referred to in Article 98(2).

SAF-K8S cybersecurity controls directly support monitoring of system robustness and security posture, including network policies (D5), workload isolation (D3), vulnerability scanning (D6 KA 6.1), and runtime security monitoring (D10). Accuracy monitoring is application-layer; cybersecurity monitoring is well-supported by SAF-K8S.

## SAF-K8S Controls

### [SAF-K8S-0204-001 - Runtime security tool deployment for syscall and network monitoring](../../controls/SAF-K8S-0204-001.md)

- Domain: D02 - Node, Runtime, and OS Security
- Knowledge Area: 2.4
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0501-001 - Default deny ingress and egress network policies](../../controls/SAF-K8S-0501-001.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0605-001 - OPA/Gatekeeper policies for Kubernetes and AI workloads](../../controls/SAF-K8S-0605-001.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.5
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0805-001 - GPU telemetry collection and anomaly detection](../../controls/SAF-K8S-0805-001.md)

- Domain: D08 - GPU, Accelerator, and Confidential Computing
- Knowledge Area: 8.5
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-1002-002 - Distributed tracing for ML pipelines](../../controls/SAF-K8S-1002-002.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.2
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

### [SAF-K8S-1005-001 - Kubernetes incident response lifecycle](../../controls/SAF-K8S-1005-001.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.5
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
