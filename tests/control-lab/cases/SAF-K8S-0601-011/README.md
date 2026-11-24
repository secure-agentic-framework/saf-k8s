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

The extended fixture also runs the pinned Zot v2.1.23 and Distribution v3.0.0
images. It verifies Ed25519 DSSE over the registry readback, rejects modified
signed bytes, and preserves the subject and referrer digests when copying
between case repositories. It stops Distribution before running filesystem
GC on the case volume and checks that eligible payloads disappear while a
separate live reference survives. OpenSSL 3 is required for the synthetic key
and signature checks. The native API arm verifies discovery with Zot. The
scheduled registry lifecycle and deployed retention authority need separate
evidence.

- [DSSE protocol](https://github.com/dsse-lf/dsse/blob/master/protocol.md)
- [In-toto statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
- [Distribution 3.0.0 garbage collection](https://github.com/distribution/distribution/blob/v3.0.0/docs/content/about/garbage-collection.md)
