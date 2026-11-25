# SAF-K8S-0602-005 OCI registry storage and Notation discovery

The case downloads checksum-pinned Notation 1.3.2 and uses disposable
Zot and Distribution registries. It verifies the native OCI Referrers
API on Zot and the OCI Referrers Tag fallback on Distribution.
Two immutable image manifests begin unsigned in each arm. Notation
signs the selected digest and verifies it using a fresh fixture trust
store. The stored signature manifest links to that exact subject,
and the unrelated image remains unsigned. A Kind Deployment uses the
native registry subject digest.

Production replication, garbage collection, trust policy, and
admission require additional deployment evidence.

[Notation v1.3.2](https://github.com/notaryproject/notation/releases/tag/v1.3.2)
· [OCI distribution specification](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#listing-referrers)

## Adopter verification

1. For each production registry and Notation client pair, record the effective discovery mode (OCI Referrers API or tag fallback) and supported versions.
2. Follow the exact image digest and signature through registry replication/copy and any tag change. verify the artifact remains discoverable and cryptographically valid at the destination.
3. Verify retention/garbage collection preserves signature artifacts with their subject and that approved trust policy and admission consume the copied artifact.
4. Keep evidence scoped per registry pair, including exceptions and service-specific behavior.
