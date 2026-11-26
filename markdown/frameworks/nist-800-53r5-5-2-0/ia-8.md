# NIST SP 800-53 Revision 5 5.2.0 - IA-8

- Framework Code: NIST-800-53R5
- Requirement Title: Identification and Authentication (Non-organizational Users)

## Mapping Notes

Authenticating external users/agents

4.2 - OIDC integration (external identity provider authentication); 7.4 - Cloud IAM to K8s RBAC mapping

## SAF-K8S Controls

### [SAF-K8S-0402-004 - Workload identity attribute integrity](../../controls/SAF-K8S-0402-004.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.2
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match

### [SAF-K8S-0402-010 - Cross-cluster and cross-cloud cryptographic identity federation](../../controls/SAF-K8S-0402-010.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.2
- Relation Type: supports
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match
