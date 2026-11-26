# NIST SP 800-53 Revision 5 5.2.0 - SC-6

- Framework Code: NIST-800-53R5
- Requirement Title: Resource Availability

## Mapping Notes

Namespace quotas allocate or cap declared requests, and PriorityClasses express scheduling preference for shared-service workloads. These mechanisms implement priority or quota allocation for the selected resources.

## SAF-K8S Controls

### [SAF-K8S-1007-007 - Cluster service protection from AI training resource exhaustion](../../controls/SAF-K8S-1007-007.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.7
- Relation Type: direct
- Strength: strong
- Applicability: conditional
- Strength Reason Code: framework-language-interpretation

### [SAF-K8S-0703-005 - AI workload resource exhaustion guardrails](../../controls/SAF-K8S-0703-005.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.3
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

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

### [SAF-K8S-0703-009 - GPU spending limits and budget enforcement](../../controls/SAF-K8S-0703-009.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.3
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0703-010 - Host-level resource isolation for AI workload nodes](../../controls/SAF-K8S-0703-010.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.3
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

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
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0101-007 - API server request concurrency and API Priority and Fairness](../../controls/SAF-K8S-0101-007.md)

- Domain: D01 - Control Plane and Cluster Hardening
- Knowledge Area: 1.1
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
