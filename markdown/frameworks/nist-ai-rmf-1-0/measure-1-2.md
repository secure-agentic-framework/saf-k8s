# NIST AI Risk Management Framework 1.0 - MEASURE 1.2

- Framework Code: NIST-AI-RMF
- Requirement Title: Appropriateness of AI metrics and effectiveness of existing controls are regularly assessed and updated, including reports of errors and potential impacts on affected communities.

## Mapping Notes

The case provides API-visible drift observations for a named namespace PSA profile, NetworkPolicy, and namespaced Role, plus a synthetic advisory/component join. These observations can inform review of selected AI-system security controls when an organization connects them to its AI-risk measurement process. They do not assess AI metric appropriateness, control effectiveness over time, error reports, community impacts, GPU telemetry, or broader accuracy, fairness, data-quality, explainability, or privacy metrics.

## SAF-K8S Controls

### [SAF-K8S-1007-004 - Continuous security posture management for AI clusters](../../controls/SAF-K8S-1007-004.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.7
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
