# EU AI Act 2024/1689 - Article-9.8

- Framework Code: EU-AI-ACT
- Requirement Title: Risk management system

## Mapping Notes

The testing of high-risk AI systems shall be performed, as appropriate, at any time throughout the development process, and, in any event, prior to their being placed on the market or put into service. Testing shall be carried out against prior defined metrics and probabilistic thresholds that are appropriate to the intended purpose of the high-risk AI system.

SAF-K8S-0905-005 supplies limited evidence for gated model checks before promotion. Confirm that the provider uses appropriate defined metrics and thresholds throughout development and before putting the system into service. Other pipeline security or environment-isolation checks do not supply that testing evidence.

## SAF-K8S Controls

### [SAF-K8S-0905-005 - Automated model promotion gates](../../controls/SAF-K8S-0905-005.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
