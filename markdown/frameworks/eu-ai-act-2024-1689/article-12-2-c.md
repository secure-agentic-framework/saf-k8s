# EU AI Act 2024/1689 - Article-12.2.c

- Framework Code: EU-AI-ACT
- Requirement Title: Record-keeping

## Mapping Notes

Article 12(2)(c) concerns event recording that supports monitoring of high-risk AI systems under Article 26(5). Relevant events depend on the system's intended purpose.

SAF-K8S telemetry forwarding can help make those events available for review. SIEM onboarding and the listed source classes are SAF implementation choices. Assess system-specific event generation and the deployer's monitoring procedure separately.
[Consolidated EU AI Act](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:02024R1689-20260727)

## SAF-K8S Controls

### [SAF-K8S-1001-028 - AI-specific SIEM source onboarding and forwarding](../../controls/SAF-K8S-1001-028.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.1
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
