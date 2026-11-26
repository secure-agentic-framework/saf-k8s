# NIST SP 800-53 Revision 5 5.2.0 - SI-5

- Framework Code: NIST-800-53R5
- Requirement Title: Security Alerts, Advisories, and Directives

## Mapping Notes

Receiving Kubernetes advisories and directing them to the assigned recipients supports the external receipt and dissemination portions of this requirement. Internal alerts and directive implementation have separate evidence.

## SAF-K8S Controls

### [SAF-K8S-0104-018 - Kubernetes security advisory and provider bulletin monitoring](../../controls/SAF-K8S-0104-018.md)

- Domain: D01 - Control Plane and Cluster Hardening
- Knowledge Area: 1.4
- Relation Type: supports
- Strength: moderate
- Applicability: required
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0902-001 - Inference server hardening](../../controls/SAF-K8S-0902-001.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.2
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
