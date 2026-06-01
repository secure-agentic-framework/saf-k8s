# NIST SP 800-53 Revision 5 5.2.0 - SI-2

- Framework Code: NIST-800-53R5
- Requirement Title: Flaw Remediation

## Mapping Notes

Flaw remediation for agent software, models, and dependencies prevents exploitation

1.4 - CVE response process (flaw remediation); 6.1 - Vulnerability scanning; 6.4 - SBOM vulnerability intelligence

## SAF-K8S Controls

### [SAF-K8S-0104-005 - Control plane configuration file permissions](../../controls/SAF-K8S-0104-005.md)

- Domain: D01 - Control Plane and Cluster Hardening
- Knowledge Area: 1.4
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match

### [SAF-K8S-0104-007 - Emergency Kubernetes patch deployment procedures](../../controls/SAF-K8S-0104-007.md)

- Domain: D01 - Control Plane and Cluster Hardening
- Knowledge Area: 1.4
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0604-001 - SBOM generation for container and AI artifacts](../../controls/SAF-K8S-0604-001.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.4
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0604-002 - ML-BOM (ML Bill of Materials) generation](../../controls/SAF-K8S-0604-002.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.4
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match

### [SAF-K8S-0604-003 - SBOM storage and distribution as OCI artifacts](../../controls/SAF-K8S-0604-003.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.4
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0604-004 - VEX (Vulnerability Exploitability eXchange) publication](../../controls/SAF-K8S-0604-004.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.4
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0604-007 - Third-party component security requirements documentation](../../controls/SAF-K8S-0604-007.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.4
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0604-010 - Automated AI workload rebuild and redeployment patch pipelines](../../controls/SAF-K8S-0604-010.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.4
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
