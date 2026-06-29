# EU AI Act 2024/1689 - Article-10.5

- Framework Code: EU-AI-ACT
- Requirement Title: Data and data governance

## Mapping Notes

To the extent that it is strictly necessary for the purpose of ensuring bias detection and correction in relation to the high-risk AI systems in accordance with paragraph (2), points (f) and (g) of this Article, the providers of such systems may exceptionally process special categories of personal data, subject to appropriate safeguards for the fundamental rights and freedoms of natural persons. In addition to the provisions set out in Regulations (EU) 2016/679 and (EU) 2018/1725 and Directive (EU) 2016/680, all the following conditions must be met in order for such processing to occur:

The authorization to process special category data is a legal obligation. However, SAF-K8S access controls (D4), encryption (D7 KA 7.1), and data classification labels (SAF-K8S-0702-006) provide the technical safeguards referenced in sub-points (b) through (e): technical limitations on re-use, security measures, access controls, and deletion enforcement.

## SAF-K8S Controls

### [SAF-K8S-0401-001 - RBAC least-privilege design](../../controls/SAF-K8S-0401-001.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0701-003 - Encryption at rest for persistent volumes](../../controls/SAF-K8S-0701-003.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
