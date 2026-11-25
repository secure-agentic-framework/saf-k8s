# NIST SP 800-53 Revision 5 5.2.0 - SC-5

- Framework Code: NIST-800-53R5
- Requirement Title: Denial-of-service Protection

## Mapping Notes

Scoped quotas, workload priorities, and service monitoring contribute to protection against capacity-related loss of service. Coverage depends on the resources and internal events designated by the organization.

## SAF-K8S Controls

### [SAF-K8S-1007-007 - Cluster service protection from AI training resource exhaustion](../../controls/SAF-K8S-1007-007.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.7
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: framework-language-interpretation

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

### [SAF-K8S-0703-007 - Fair-share GPU queue management for multi-tenant clusters](../../controls/SAF-K8S-0703-007.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.3
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0703-008 - Idle GPU detection and resource reclamation](../../controls/SAF-K8S-0703-008.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.3
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0703-010 - Host-level resource isolation for AI workload nodes](../../controls/SAF-K8S-0703-010.md)

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

### [SAF-K8S-0703-014 - EDoS spending guardrails and autoscaling limits for AI resources](../../controls/SAF-K8S-0703-014.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.3
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match

### [SAF-K8S-0903-001 - Adversarial example defenses at the serving layer](../../controls/SAF-K8S-0903-001.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.3
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match

### [SAF-K8S-0903-003 - Inference-time resource controls](../../controls/SAF-K8S-0903-003.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.3
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0903-004 - LLM context window and token resource controls](../../controls/SAF-K8S-0903-004.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.3
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
