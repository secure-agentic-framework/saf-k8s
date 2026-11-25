# EU AI Act 2024/1689 - Article-4a.1.b

- Framework Code: EU-AI-ACT
- Requirement Title: Technical limitations on re-use and security/privacy safeguards

## Mapping Notes

PV/PVC access-mode, claim-use and effective backend access controls can contribute technical limits on re-use for the covered data. The full safeguard includes separate privacy measures and pseudonymisation. The former Article-10.5.b locator comes from Regulation (EU) 2024/1689. Regulation (EU) 2026/1744 deletes Article 10(5) and inserts Article 4a. Article 4a(2)(b) applies paragraph 1 safeguards where applicable. Official text https://eur-lex.europa.eu/eli/reg/2026/1744/oj/eng.

## SAF-K8S Controls

### [SAF-K8S-0701-001 - PersistentVolume and PersistentVolumeClaim access mode enforcement](../../controls/SAF-K8S-0701-001.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.1
- Relation Type: partial
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0701-003 - Encryption at rest for persistent volumes](../../controls/SAF-K8S-0701-003.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.1
- Relation Type: partial
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0702-019 - Supplementary namespace isolation control enforcement for multi-tenant AI clusters](../../controls/SAF-K8S-0702-019.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.2
- Relation Type: partial
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
