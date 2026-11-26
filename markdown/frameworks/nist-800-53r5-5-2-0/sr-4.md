# NIST SP 800-53 Revision 5 5.2.0 - SR-4

- Framework Code: NIST-800-53R5
- Requirement Title: Provenance

## Mapping Notes

The control contributes one handoff record linking the authenticated producer/observer identity, artifact digest, signed evidence and receiving decision. It does not establish end-to-end provenance for AI models, training data, tools, dependencies, or all lifecycle stages. NIST SP 800-53 Rev. 5 SR-4 concerns documenting, monitoring and maintaining provenance of systems and system components; retain this conditional contribution only where this handoff is incorporated into that provenance record.

## SAF-K8S Controls

### [SAF-K8S-0606-018 - Zero-trust CI/CD handoff verification and independent evidence generation](../../controls/SAF-K8S-0606-018.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.6
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0905-009 - Model provenance verification at deployment](../../controls/SAF-K8S-0905-009.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0905-047 - Training pipeline attestation generation for ML artifacts](../../controls/SAF-K8S-0905-047.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0905-056 - External model publisher identity and provenance metadata verification](../../controls/SAF-K8S-0905-056.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0910-024 - Cross-cluster model provenance chain-of-custody preservation](../../controls/SAF-K8S-0910-024.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.10
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
