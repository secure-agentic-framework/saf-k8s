# EU AI Act 2024/1689 - Annex-XI.2.2

- Framework Code: EU-AI-ACT
- Requirement Title: Technical documentation referred to in Article 53(1), point (a) — technical documentation for providers of general-purpose AI models

## Mapping Notes

Where applicable, a detailed description of the measures put in place for the purpose of conducting internal and/or external adversarial testing (e.g. red teaming), model adaptations, including alignment and fine-tuning.

SAF-K8S provides infrastructure-level safety measures: workload isolation (D3), resource limits (D8), network segmentation (D5), and monitoring (D10). Application-layer safety measures (guardrails, content filtering) are outside SAF-K8S scope but run on SAF-K8S-managed infrastructure.

## SAF-K8S Controls

### [SAF-K8S-0302-001 - Pod and container security context enforcement](../../controls/SAF-K8S-0302-001.md)

- Domain: D03 - Workload and Pod Security
- Knowledge Area: 3.2
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0304-011 - Namespace LimitRange and ResourceQuota enforcement](../../controls/SAF-K8S-0304-011.md)

- Domain: D03 - Workload and Pod Security
- Knowledge Area: 3.4
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0601-008 - CI/CD build-time container image vulnerability scanning](../../controls/SAF-K8S-0601-008.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0604-002 - ML-BOM (ML Bill of Materials) generation](../../controls/SAF-K8S-0604-002.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.4
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation

### [SAF-K8S-0606-011 - CI build-time security gate enforcement](../../controls/SAF-K8S-0606-011.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.6
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0903-001 - Adversarial example defenses at the serving layer](../../controls/SAF-K8S-0903-001.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.3
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation

### [SAF-K8S-0905-006 - Model artifact lifecycle management](../../controls/SAF-K8S-0905-006.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation

### [SAF-K8S-1002-003 - AI workload telemetry integration into cluster monitoring](../../controls/SAF-K8S-1002-003.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.2
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
