# NIST AI Risk Management Framework 1.0 - GOVERN 4.3

- Framework Code: NIST-AI-RMF
- Requirement Title: Organizational practices are in place to enable AI testing, identification of incidents, and information sharing.

## Mapping Notes

A monitored node clock can support sequencing and correlation of AI test and incident records. Incident procedures, investigation, and information sharing require their own evidence.

## SAF-K8S Controls

### [SAF-K8S-0203-016 - Node time synchronization with authoritative time sources](../../controls/SAF-K8S-0203-016.md)

- Domain: D02 - Node, Runtime, and OS Security
- Knowledge Area: 2.3
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: n/a

### [SAF-K8S-1005-001 - Kubernetes incident response lifecycle](../../controls/SAF-K8S-1005-001.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.5
- Relation Type: supports
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation
