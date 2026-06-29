# EU AI Act 2024/1689 - Annex-IV.1.b

- Framework Code: EU-AI-ACT
- Requirement Title: Technical documentation referred to in Article 11(1)

## Mapping Notes

how the AI system interacts with, or can be used to interact with, hardware or software, including with other AI systems, that are not part of the AI system itself, where applicable;

SAF-K8S captures service mesh topology, API gateway configurations, and workload interconnection patterns for AI systems deployed on Kubernetes. Full product-level integration documentation is an organizational responsibility.

## SAF-K8S Controls

### [SAF-K8S-0504-002 - Service mesh mTLS and authorization policies](../../controls/SAF-K8S-0504-002.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.4
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0702-005 - Label and annotation schema definition for AI workload classification](../../controls/SAF-K8S-0702-005.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.2
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation
