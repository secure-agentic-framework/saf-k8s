# EU AI Act 2024/1689 - Article-55.1.d

- Framework Code: EU-AI-ACT
- Requirement Title: Obligations of providers of general-purpose AI models with systemic risk

## Mapping Notes

ensure an adequate level of cybersecurity protection for the general-purpose AI model with systemic risk and the physical infrastructure of the model.

SAF-K8S comprehensively covers cybersecurity measures across all 10 domains: network security (D5), access control (D4), workload isolation (D3), supply chain integrity (D6), GPU security (D8), and incident response (D10). Security testing infrastructure and evaluation results are managed through SAF-K8S pipelines.

## SAF-K8S Controls

### [SAF-K8S-0302-001 - Pod and container security context enforcement](../../controls/SAF-K8S-0302-001.md)

- Domain: D03 - Workload and Pod Security
- Knowledge Area: 3.2
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0401-001 - RBAC least-privilege design](../../controls/SAF-K8S-0401-001.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0501-001 - Default deny ingress and egress network policies](../../controls/SAF-K8S-0501-001.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.1
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

### [SAF-K8S-0801-001 - GPU device plugin security configuration and hardening](../../controls/SAF-K8S-0801-001.md)

- Domain: D08 - GPU, Accelerator, and Confidential Computing
- Knowledge Area: 8.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-1005-001 - Kubernetes incident response lifecycle](../../controls/SAF-K8S-1005-001.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.5
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
