# EU AI Act 2024/1689 - Article-14.3.a

- Framework Code: EU-AI-ACT
- Requirement Title: Human oversight

## Mapping Notes

measures identified and built, when technically feasible, into the high-risk AI system by the provider before it is placed on the market or put into service;

Kubernetes admission policy (SAF-K8S-0605-001) and automated model promotion gates (SAF-K8S-0905-005) can support provider-designed safeguards before deployment. Where promotion includes human approval, SAF-K8S-0905-025 addresses separation of duties, SAF-K8S-0905-050 addresses reviewer authentication, and SAF-K8S-0905-051 addresses approval audit binding. Effective human oversight during use also requires the relevant system capabilities and operational evidence.

## SAF-K8S Controls

### [SAF-K8S-0605-001 - OPA/Gatekeeper policies for Kubernetes and AI workloads](../../controls/SAF-K8S-0605-001.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.5
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
