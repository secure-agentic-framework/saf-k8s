# SAF-K8S-0601-011 — OCI integrity metadata co-retention

```sh
python3 lab.py test SAF-K8S-0601-011 --docker-context desktop-linux
```

Evaluate fixture retention records with immutable OCI descriptors.
Independent expiry produces an early-deletion plan and an orphan finding.
The cohort policy holds unmatched metadata and retains valid referrers while
their subject is retained.

The live arm starts a digest-pinned, loopback-only OCI Distribution registry
within the local Docker context. Two case repositories receive only synthetic
subject, signature, attestation and SBOM manifests. The baseline shows a
referrer can disappear while its subject remains. The guarded flow preserves
the subject and all three referrers before eligibility and removes them after
eligible retirement. The registry profile uses the OCI fallback referrers tag
when the native listing API returns 404. Retirement also removes that index.
The test records which discovery mechanism the actual registry used.

The OCI objects contain public fixture metadata. Signature validity,
cross-repository replication, provider garbage collection, scheduled
production retention and recovery need separate evidence. Both the case
registry and the disposable Kubernetes cluster are removed.

- [OCI Distribution 1.1.1 referrer discovery and tag fallback](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md)
- [OCI Image Manifest 1.1.1](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md)
