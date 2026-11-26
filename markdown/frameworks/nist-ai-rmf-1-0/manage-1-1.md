# NIST AI Risk Management Framework 1.0 - MANAGE 1.1

- Framework Code: NIST-AI-RMF
- Requirement Title: A determination is made as to whether the AI system achieves its intended purposes and stated objectives and whether its development or deployment should proceed.

## Mapping Notes

The fixture makes a mechanical allow/deny decision for a Deployment whose declared lifecycle class and profile match a named synthetic registry record. It does not determine whether an AI system achieves intended purposes or objectives, nor whether deployment should proceed on that basis. Treat it only as one metadata prerequisite in a larger decision process.

## SAF-K8S Controls

### [SAF-K8S-0905-001 - AI system lifecycle classification](../../controls/SAF-K8S-0905-001.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: partial
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0905-005 - Automated model promotion gates](../../controls/SAF-K8S-0905-005.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: partial
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0606-018 - Zero-trust CI/CD handoff verification and independent evidence generation](../../controls/SAF-K8S-0606-018.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.6
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0910-018 - Security-aware target-cluster posture verification before multi-cluster placement](../../controls/SAF-K8S-0910-018.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
