# NIST AI Risk Management Framework 1.0 - MEASURE 1.1

- Framework Code: NIST-AI-RMF
- Requirement Title: Approaches and metrics for measurement of AI risks enumerated during the MAP function are selected for implementation starting with the most significant AI risks. The risks or outcomes that cannot be measured through quantitative means are addressed qualitatively.

## Mapping Notes

The portable case proves W3C context propagation and trace parentage across synthetic ingestion, a native training Job, registry, and inference/KServe. Trace context can provide evidence inputs to selected AI-risk measurement approaches; it does not select risk metrics or evaluate AI outcomes.

## SAF-K8S Controls

### [SAF-K8S-1002-002 - Distributed tracing for ML pipelines](../../controls/SAF-K8S-1002-002.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.2
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
