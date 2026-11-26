# NIST AI Risk Management Framework 1.0 - MEASURE 3.1

- Framework Code: NIST-AI-RMF
- Requirement Title: Approaches, personnel, and documentation are in place to regularly identify and track existing, unanticipated, and emergent AI risks based on factors such as intended and actual performance in deployed contexts.

## Mapping Notes

This control may contribute one external-threat-information input to MEASURE 3.1 only where the adopter uses current validated threat information to identify and track risks for actual AI systems in deployed contexts, with documented approaches and accountable personnel. The portable case verifies offline pin, change and expiry quarantine and one synthetic advisory-to-observation match. It does not prove live source authenticity, freshness/completeness, runtime coverage, deployed-context performance assessment, or an organizational risk-tracking process.

## SAF-K8S Controls

### [SAF-K8S-1004-004 - Kubernetes AI threat intelligence feed ingestion and detection enrichment](../../controls/SAF-K8S-1004-004.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.4
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-1007-004 - Continuous security posture management for AI clusters](../../controls/SAF-K8S-1007-004.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.7
- Relation Type: supports
- Strength: weak
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
