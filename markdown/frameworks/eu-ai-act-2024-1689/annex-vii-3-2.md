# EU AI Act 2024/1689 - Annex-VII.3.2

- Framework Code: EU-AI-ACT
- Requirement Title: Conformity based on an assessment of the quality management system and an assessment of the technical documentation

## Mapping Notes

The quality management system shall be assessed by the notified body, which shall determine whether it satisfies the requirements referred to in Article 17.

SAF-K8S CI/CD pipeline controls (D6), automated testing infrastructure, validation pipelines (D9), and observability stack (D10) provide infrastructure evidence of development, testing, validation, and monitoring processes. However, the notified body assessment evaluates organizational processes holistically, not just infrastructure artifacts.

## SAF-K8S Controls

### [SAF-K8S-1002-003 - AI workload telemetry integration into cluster monitoring](../../controls/SAF-K8S-1002-003.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.2
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-1006-004 - Automated audit readiness for Kubernetes AI platforms](../../controls/SAF-K8S-1006-004.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.6
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
