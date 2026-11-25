# SAF-K8S-0803-005 Device boot and revision evidence policy

OpenSSL verifies an inert signed record. A live Kubernetes Job classifies device binding, signature, freshness, expected revision, and the separate modeled boot observation. Public fixture vectors are included. This case does not authenticate a real DPU or measure firmware, a boot chain, or enforced device state.

## Adopter verification

1. Inventory the relevant accelerator, firmware and platform trust chain and identify the authoritative attestation source and approved measurements or versions.
2. Collect signed per-device evidence from sanctioned nodes. Validate issuer, device identity, freshness and independent boot observations. Verify that approved evidence permits the expected workflow and that stale, mismatched or unverifiable evidence is rejected or escalated.
3. Retain sanitized device identity, firmware recommendations and version, trusted root or endorsement, appraisal outcome, ownership and observed gaps. Reverify after firmware or hardware changes.
