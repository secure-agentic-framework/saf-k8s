# EU AI Act 2024/1689 - Article-10.5.b

- Framework Code: EU-AI-ACT
- Requirement Title: Data and data governance

## Mapping Notes

the special categories of personal data are subject to technical limitations on the re-use of the personal data, and state-of-the-art security and privacy-preserving measures, including pseudonymisation;

SAF-K8S enforces technical limitations on data re-use through storage access controls, namespace isolation, data classification labels, and encryption at rest and in transit. However, pseudonymisation is an application-layer data transformation that SAF-K8S does not perform.

## SAF-K8S Controls

### [SAF-K8S-0701-001 - PersistentVolume and PersistentVolumeClaim access mode enforcement](../../controls/SAF-K8S-0701-001.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation

### [SAF-K8S-0701-003 - Encryption at rest for persistent volumes](../../controls/SAF-K8S-0701-003.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0702-019 - Supplementary namespace isolation control enforcement for multi-tenant AI clusters](../../controls/SAF-K8S-0702-019.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.2
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation
