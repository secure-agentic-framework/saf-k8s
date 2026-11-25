# NIST AI Risk Management Framework 1.0 - MEASURE 2.3

- Framework Code: NIST-AI-RMF
- Requirement Title: AI system performance or assurance criteria are measured qualitatively or quantitatively and demonstrated for conditions similar to deployment setting(s). Measures are documented.

## Mapping Notes

The portable case establishes trace context and parentage across synthetic pipeline services and a KServe predictor, including an inert inference error marker. It does not measure an AI-system performance or assurance criterion, demonstrate deployment-setting performance, or document AI trustworthiness results. Use trace data as evidence only when it is connected to a defined criterion and separately documented measurement.

## SAF-K8S Controls

### [SAF-K8S-1002-002 - Distributed tracing for ML pipelines](../../controls/SAF-K8S-1002-002.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.2
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
