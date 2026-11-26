# EU AI Act 2024/1689 - Annex-VIII.A.4

- Framework Code: EU-AI-ACT
- Requirement Title: Information to be submitted upon the registration of high-risk AI systems in accordance with Article 49

## Mapping Notes

If this signed image digest is explicitly linked to the registered high-risk AI system as an unambiguous traceability reference. The fixture identifies one OCI image digest, not the AI system trade name, system-level registration identifier, model version, or model-to-system linkage. Those identifiers and relationships must be maintained separately.

## SAF-K8S Controls

### [SAF-K8S-0602-001 - Sigstore/cosign keyless signing and Rekor transparency logging](../../controls/SAF-K8S-0602-001.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.2
- Relation Type: partial
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0604-002 - ML-BOM (ML Bill of Materials) generation](../../controls/SAF-K8S-0604-002.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.4
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation

### [SAF-K8S-0702-005 - Label and annotation schema definition for AI workload classification](../../controls/SAF-K8S-0702-005.md)

- Domain: D07 - Storage, Multi-tenancy, and Resource Governance
- Knowledge Area: 7.2
- Relation Type: partial
- Strength: moderate
- Applicability: required
- Strength Reason Code: framework-language-interpretation
