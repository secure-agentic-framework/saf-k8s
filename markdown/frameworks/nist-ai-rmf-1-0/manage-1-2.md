# NIST AI Risk Management Framework 1.0 - MANAGE 1.2

- Framework Code: NIST-AI-RMF
- Requirement Title: Treatment of documented AI risks is prioritized based on impact, likelihood, and available resources or methods.

## Mapping Notes

This four-check fixture supplies limited context for a separate AI risk-treatment decision: it observes Job/Deployment ownership and node/runtime-image identities, resolves fictional component inventory matches and conflicts, and verifies a private inference service path. The paired run does not perform or evidence prioritization. Use the relation only when those facts are incorporated into the organization’s documented AI risk assessment and treatment process.

## SAF-K8S Controls

### [SAF-K8S-0604-008 - AI workload vulnerability exposure classification](../../controls/SAF-K8S-0604-008.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.4
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-1003-002 - OCTAVE risk-based threat assessment for Kubernetes AI environments](../../controls/SAF-K8S-1003-002.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.3
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match
