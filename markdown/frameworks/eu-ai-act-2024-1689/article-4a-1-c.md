# EU AI Act 2024/1689 - Article-4a.1.c

- Framework Code: EU-AI-ACT
- Requirement Title: Safeguards for special categories of personal data processed for bias detection and correction

## Mapping Notes

Documented least-privilege Kubernetes grants can restrict access to the relevant API resources and identities. Evidence of data-level coverage, access documentation and confidentiality is assessed separately. Regulation (EU) 2026/1744 deletes Article 10(5) and inserts Article 4a in Regulation (EU) 2024/1689. Article 4a(2)(b) applies paragraph 1 conditions and safeguards to the actors listed there. See Article 4 and recital 9 of Regulation (EU) 2026/1744 for entry into force and application timing. Official text https://eur-lex.europa.eu/eli/reg/2026/1744/oj/eng.

## SAF-K8S Controls

### [SAF-K8S-0401-001 - RBAC least-privilege design](../../controls/SAF-K8S-0401-001.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.1
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0401-002 - RBAC permission audit and analysis](../../controls/SAF-K8S-0401-002.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.1
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0701-003 - Encryption at rest for persistent volumes](../../controls/SAF-K8S-0701-003.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.1
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
