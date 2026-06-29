# EU AI Act 2024/1689 - Article-15.4

- Framework Code: EU-AI-ACT
- Requirement Title: Accuracy, robustness and cybersecurity

## Mapping Notes

High-risk AI systems shall be as resilient as possible regarding errors, faults or inconsistencies that may occur within the system or the environment in which the system operates, in particular due to their interaction with natural persons or other systems. Technical and organisational measures shall be taken in this regard. The robustness of high-risk AI systems may be achieved through technical redundancy solutions, which may include backup or fail-safe plans. High-risk AI systems that continue to learn after being placed on the market or put into service shall be developed in such a way as to eliminate or reduce as far as possible the risk of possibly biased outputs influencing input for future operations (feedback loops), and as to ensure that any such feedback loops are duly addressed with appropriate mitigation measures.

Kubernetes provides infrastructure redundancy through replica sets, multi-zone scheduling, PDBs, etcd backups, and disaster recovery controls (SAF-K8S D1, D7, D10).

## SAF-K8S Controls

### [SAF-K8S-0102-008 - etcd backup integrity verification and restore assurance](../../controls/SAF-K8S-0102-008.md)

- Domain: D01 - Control Plane and Cluster Hardening
- Knowledge Area: 1.2
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0304-011 - Namespace LimitRange and ResourceQuota enforcement](../../controls/SAF-K8S-0304-011.md)

- Domain: D03 - Workload and Pod Security
- Knowledge Area: 3.4
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0703-002 - Pod Disruption Budgets for workload availability](../../controls/SAF-K8S-0703-002.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.3
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0703-005 - AI workload resource exhaustion guardrails](../../controls/SAF-K8S-0703-005.md)

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

### [SAF-K8S-0901-003 - Checkpoint security](../../controls/SAF-K8S-0901-003.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0901-004 - Training fault tolerance and security](../../controls/SAF-K8S-0901-004.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0906-002 - Large-scale data integrity verification](../../controls/SAF-K8S-0906-002.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.6
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
