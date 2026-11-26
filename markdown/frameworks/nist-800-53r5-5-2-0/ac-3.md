# NIST SP 800-53 Revision 5 5.2.0 - AC-3

- Framework Code: NIST-800-53R5
- Requirement Title: Access Enforcement

## Mapping Notes

Core to agent authorization -- enforcing what agents can do

4.1 - Design and enforce RBAC (least-privilege access enforcement for all Kubernetes resources)

## SAF-K8S Controls

### [SAF-K8S-0401-001 - RBAC least-privilege design](../../controls/SAF-K8S-0401-001.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0401-002 - RBAC permission audit and analysis](../../controls/SAF-K8S-0401-002.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0401-003 - Aggregated ClusterRole governance](../../controls/SAF-K8S-0401-003.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0401-004 - RBAC for AI operator custom resources](../../controls/SAF-K8S-0401-004.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0902-008 - Inference endpoint authentication and authorization](../../controls/SAF-K8S-0902-008.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.2
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-1002-001 - Metric endpoint authentication](../../controls/SAF-K8S-1002-001.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.2
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0501-009 - Model download path isolation from training data paths](../../controls/SAF-K8S-0501-009.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.1
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
