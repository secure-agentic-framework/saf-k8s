# EU AI Act 2024/1689 - Article-4a.1.e

- Framework Code: EU-AI-ACT
- Requirement Title: Deletion of special-category personal data

## Mapping Notes

Storage deletion or reclaim behavior can contribute when the earlier of bias correction or retention expiry is enforced for every covered copy. Verify backing storage and recovery artifacts separately. The former Article-10.5.e locator comes from Regulation (EU) 2024/1689. Regulation (EU) 2026/1744 deletes Article 10(5) and inserts Article 4a. Article 4a(2)(b) applies paragraph 1 safeguards where applicable. Official text https://eur-lex.europa.eu/eli/reg/2026/1744/oj/eng.

## SAF-K8S Controls

### [SAF-K8S-0701-004 - PV reclaim policy enforcement for AI data volumes](../../controls/SAF-K8S-0701-004.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.1
- Relation Type: partial
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-1007-006 - Secure AI workload decommissioning](../../controls/SAF-K8S-1007-006.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.7
- Relation Type: partial
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
