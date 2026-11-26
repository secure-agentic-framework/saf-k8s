# NIST SP 800-53 Revision 5 5.2.0 - SI-2

- Framework Code: NIST-800-53R5
- Requirement Title: Flaw Remediation

## Mapping Notes

An approved and validated emergency patch supports correction and installation for the affected Kubernetes component. Identification, issue tracking and broader configuration management have separate evidence.

## SAF-K8S Controls

### [SAF-K8S-0104-007 - Emergency Kubernetes patch deployment procedures](../../controls/SAF-K8S-0104-007.md)

- Domain: D01 - Control Plane and Cluster Hardening
- Knowledge Area: 1.4
- Relation Type: supports
- Strength: moderate
- Applicability: required
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0604-002 - ML-BOM (ML Bill of Materials) generation](../../controls/SAF-K8S-0604-002.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.4
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match

### [SAF-K8S-0604-010 - Automated AI workload rebuild and redeployment patch pipelines](../../controls/SAF-K8S-0604-010.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.4
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0902-001 - Inference server hardening](../../controls/SAF-K8S-0902-001.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.2
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
