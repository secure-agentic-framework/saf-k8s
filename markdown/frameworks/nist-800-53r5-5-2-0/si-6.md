# NIST SP 800-53 Revision 5 5.2.0 - SI-6

- Framework Code: NIST-800-53R5
- Requirement Title: Security and Privacy Function Verification

## Mapping Notes

Verification of agent security functions ensures controls operate as intended

10.7 - Security posture management (verifying security function effectiveness); 7.3 - Chaos engineering

## SAF-K8S Controls

### [SAF-K8S-0703-008 - Idle GPU detection and resource reclamation](../../controls/SAF-K8S-0703-008.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.3
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0703-012 - Node affinity rules, taints, and tolerations for AI workload isolation](../../controls/SAF-K8S-0703-012.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.3
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match

### [SAF-K8S-1007-006 - Secure AI workload decommissioning](../../controls/SAF-K8S-1007-006.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.7
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
