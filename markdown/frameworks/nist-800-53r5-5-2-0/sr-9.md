# NIST SP 800-53 Revision 5 5.2.0 - SR-9

- Framework Code: NIST-800-53R5
- Requirement Title: Tamper Resistance and Detection

## Mapping Notes

Where pre-use signature verification is one control for detecting unauthorized changes to the covered software image. The fixture verifies the digest before use; it does not provide tamper resistance or detection during runtime, component inspection, or continuous integrity monitoring.

## SAF-K8S Controls

### [SAF-K8S-0602-001 - Sigstore/cosign keyless signing and Rekor transparency logging](../../controls/SAF-K8S-0602-001.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.2
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage

### [SAF-K8S-0802-001 - GPU driver lifecycle and vulnerability management](../../controls/SAF-K8S-0802-001.md)

- Domain: D08 - GPU, Accelerator, and Confidential Computing
- Knowledge Area: 8.2
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0802-002 - CUDA library and container toolkit security](../../controls/SAF-K8S-0802-002.md)

- Domain: D08 - GPU, Accelerator, and Confidential Computing
- Knowledge Area: 8.2
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0802-004 - GPU firmware integrity monitoring](../../controls/SAF-K8S-0802-004.md)

- Domain: D08 - GPU, Accelerator, and Confidential Computing
- Knowledge Area: 8.2
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a
