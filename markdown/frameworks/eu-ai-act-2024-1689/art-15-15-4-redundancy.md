# EU AI Act 2024/1689 - Art-15:15(4)-redundancy

- Framework Code: EU-AI-ACT
- Requirement Title: Accuracy, Robustness and Cybersecurity

## Mapping Notes

The robustness of high-risk AI systems may be achieved through technical redundancy solutions, which may include backup or fail-safe plans.

Kubernetes provides infrastructure redundancy through replica sets, multi-zone scheduling, PDBs, etcd backups, and disaster recovery controls (SAF-K8S D1, D7, D10).

## SAF-K8S Controls

### [SAF-K8S-0102-008 - etcd backup integrity verification and restore assurance](../../controls/SAF-K8S-0102-008.md)

- Domain: D01 - Control Plane and Cluster Hardening
- Knowledge Area: 1.2
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

### [SAF-K8S-0703-012 - Node affinity rules, taints, and tolerations for AI workload isolation](../../controls/SAF-K8S-0703-012.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.3
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match

### [SAF-K8S-0901-004 - Training fault tolerance and security](../../controls/SAF-K8S-0901-004.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
