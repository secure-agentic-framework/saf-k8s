# NIST AI Risk Management Framework 1.0 - GOVERN 6.1

- Framework Code: NIST-AI-RMF
- Requirement Title: Policies and procedures are in place that address AI risks associated with third-party entities, including risks of infringement of a third-party's intellectual property or other rights.

## Mapping Notes

SBOM and ML-BOM generation documents third-party dependencies. CNCF lifecycle security and zero-trust CI/CD pipelines enforce supply chain controls. Restricted use policies govern external AI service consumption.

## SAF-K8S Controls

### [SAF-K8S-0604-001 - SBOM generation for container and AI artifacts](../../controls/SAF-K8S-0604-001.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.4
- Relation Type: supports
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation

### [SAF-K8S-0604-002 - ML-BOM (ML Bill of Materials) generation](../../controls/SAF-K8S-0604-002.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.4
- Relation Type: supports
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation

### [SAF-K8S-0704-005 - Restricted use policies for non-organizationally owned systems and external AI services](../../controls/SAF-K8S-0704-005.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.4
- Relation Type: supports
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation
