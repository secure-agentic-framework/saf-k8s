# EU AI Act 2024/1689 - Article-60.1

- Framework Code: EU-AI-ACT
- Requirement Title: Testing of high-risk AI systems in real world conditions outside AI regulatory sandboxes

## Mapping Notes

Testing of high-risk AI systems in real world conditions outside AI regulatory sandboxes may be conducted by providers or prospective providers of high-risk AI systems listed in Annex III, in accordance with this Article and the real-world testing plan referred to in this Article, without prejudice to the prohibitions under Article 5. The Commission shall, by means of implementing acts, specify the detailed elements of the real-world testing plan. Those implementing acts shall be adopted in accordance with the examination procedure referred to in Article 98(2). This paragraph shall be without prejudice to Union or national law on the testing in real world conditions of high-risk AI systems related to products covered by Union harmonisation legislation listed in Annex I.

SAF-K8S provides technical safeguards relevant to real-world testing: workload isolation (D3), network segmentation (D5), access controls (D4), and data protection controls (D7). Fundamental rights protections and organizational safeguards are outside SAF-K8S scope.

## SAF-K8S Controls

### [SAF-K8S-0302-001 - Pod and container security context enforcement](../../controls/SAF-K8S-0302-001.md)

- Domain: D03 - Workload and Pod Security
- Knowledge Area: 3.2
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0401-001 - RBAC least-privilege design](../../controls/SAF-K8S-0401-001.md)

- Domain: D04 - Identity, Access, and Secrets Management
- Knowledge Area: 4.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0501-001 - Default deny ingress and egress network policies](../../controls/SAF-K8S-0501-001.md)

- Domain: D05 - Network Security and Communication
- Knowledge Area: 5.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0701-001 - PersistentVolume and PersistentVolumeClaim access mode enforcement](../../controls/SAF-K8S-0701-001.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation

### [SAF-K8S-0701-003 - Encryption at rest for persistent volumes](../../controls/SAF-K8S-0701-003.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.1
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: n/a
