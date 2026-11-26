# NIST SP 800-53 Revision 5 5.2.0 - IA-9

- Framework Code: NIST-800-53R5
- Requirement Title: Service Identification and Authentication

## Mapping Notes

The actual API path verifies the expected certificate-backed identity of each selected extension endpoint.

## SAF-K8S Controls

### [SAF-K8S-0404-002 - TLS provisioning for webhooks, API aggregation, and internal services](../../controls/SAF-K8S-0404-002.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.4
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: n/a

### [SAF-K8S-0404-003 - mTLS for service-to-service authentication](../../controls/SAF-K8S-0404-003.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.4
- Relation Type: direct
- Strength: strong
- Applicability: conditional
- Strength Reason Code: n/a

### [SAF-K8S-0504-001 - Zero trust networking principles for Kubernetes](../../controls/SAF-K8S-0504-001.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.4
- Relation Type: supports
- Strength: moderate
- Applicability: required
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0504-002 - Service mesh mTLS and authorization policies](../../controls/SAF-K8S-0504-002.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.4
- Relation Type: supports
- Strength: moderate
- Applicability: required
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0910-004 - Federated learning cross-cluster coordination security](../../controls/SAF-K8S-0910-004.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0910-016 - Cross-cluster orchestration identity federation and authorization](../../controls/SAF-K8S-0910-016.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: partial
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0910-021 - Cross-cluster endpoint and workload authentication for AI communication](../../controls/SAF-K8S-0910-021.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: n/a

### [SAF-K8S-0910-030 - Cross-cluster registry replication channel mutual authentication](../../controls/SAF-K8S-0910-030.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-1002-001 - Metric endpoint authentication](../../controls/SAF-K8S-1002-001.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.2
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0501-006 - Multi-cluster network segmentation for federated AI workloads](../../controls/SAF-K8S-0501-006.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.1
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
