# EU AI Act 2024/1689 - Article-10.2

- Framework Code: EU-AI-ACT
- Requirement Title: Data and data governance

## Mapping Notes

Training, validation and testing data sets shall be subject to data governance and management practices appropriate for the intended purpose of the high-risk AI system. Those practices shall concern in particular:

SAF-K8S-0701-001 supplies limited storage-access evidence. SAF-K8S-0702-027 addresses application and coverage of classification labels across governed pipelines. Evidence of those mechanisms supports the applicable infrastructure portions of data governance. Suitability for the intended purpose remains a provider assessment.

## SAF-K8S Controls

### [SAF-K8S-0701-001 - PersistentVolume and PersistentVolumeClaim access mode enforcement](../../controls/SAF-K8S-0701-001.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation

### [SAF-K8S-0702-019 - Supplementary namespace isolation control enforcement for multi-tenant AI clusters](../../controls/SAF-K8S-0702-019.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.2
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation
