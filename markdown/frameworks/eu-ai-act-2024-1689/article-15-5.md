# EU AI Act 2024/1689 - Article-15.5

- Framework Code: EU-AI-ACT
- Requirement Title: Accuracy, robustness and cybersecurity

## Mapping Notes

High-risk AI systems shall be resilient against attempts by unauthorised third parties to alter their use, outputs or performance by exploiting system vulnerabilities. The technical solutions aiming to ensure the cybersecurity of high-risk AI systems shall be appropriate to the relevant circumstances and the risks. The technical solutions to address AI specific vulnerabilities shall include, where appropriate, measures to prevent, detect, respond to, resolve and control for attacks trying to manipulate the training data set (data poisoning), or pre-trained components used in training (model poisoning), inputs designed to cause the AI model to make a mistake (adversarial examples or model evasion), confidentiality attacks or model flaws.

Risk-appropriate cybersecurity is the fundamental SAF-K8S design principle. Controls are tiered by maturity level and archetype to match circumstances and risk profiles.

## SAF-K8S Controls

### [SAF-K8S-0104-015 - CIS Benchmark result retention and posture trend reporting](../../controls/SAF-K8S-0104-015.md)

- Domain: D01 - Control Plane and Cluster Hardening
- Knowledge Area: 1.4
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0204-001 - Runtime security tool deployment for syscall and network monitoring](../../controls/SAF-K8S-0204-001.md)

- Domain: D02 - Node, Runtime, and OS Security
- Knowledge Area: 2.4
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0301-001 - Pod Security Standards level assignment](../../controls/SAF-K8S-0301-001.md)

- Domain: D03 - Workload and Pod Security
- Knowledge Area: 3.1
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match

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

### [SAF-K8S-0605-001 - OPA/Gatekeeper policies for Kubernetes and AI workloads](../../controls/SAF-K8S-0605-001.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.5
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0902-003 - Inference request validation and input sanitization](../../controls/SAF-K8S-0902-003.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.2
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0903-001 - Adversarial example defenses at the serving layer](../../controls/SAF-K8S-0903-001.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.3
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match

### [SAF-K8S-0905-001 - AI system lifecycle classification](../../controls/SAF-K8S-0905-001.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match

### [SAF-K8S-0906-004 - Statistical drift, outlier, and input validation for training data poisoning detection](../../controls/SAF-K8S-0906-004.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.6
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: exact-text-match

### [SAF-K8S-0908-001 - Oracle attack prevention](../../controls/SAF-K8S-0908-001.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.8
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0908-002 - Inference API information exposure controls](../../controls/SAF-K8S-0908-002.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.8
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-1007-004 - Continuous security posture management for AI clusters](../../controls/SAF-K8S-1007-004.md)

- Domain: D10 - Observability, Incident Response, and Governance
- Knowledge Area: 10.7
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
