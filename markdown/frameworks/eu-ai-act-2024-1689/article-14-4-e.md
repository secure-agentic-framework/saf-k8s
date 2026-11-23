# EU AI Act 2024/1689 - Article-14.4.e

- Framework Code: EU-AI-ACT
- Requirement Title: Human oversight

## Mapping Notes

to intervene in the operation of the high-risk AI system or interrupt the system through a stop button or a similar procedure that allows the system to come to a halt in a safe state.

Verified network isolation can contribute to a stop procedure where trained overseers have actual authority to use it. SAF-K8S-1005-024 supplies limited quarantine and suspension mechanisms in incident response. Independently verify the safe-state behavior and the available procedure.

## SAF-K8S Controls

### [SAF-K8S-0501-001 - Default deny ingress and egress network policies](../../controls/SAF-K8S-0501-001.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.1
- Relation Type: partial
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-1005-001 - Kubernetes incident response lifecycle](../../controls/SAF-K8S-1005-001.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.5
- Relation Type: partial
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
