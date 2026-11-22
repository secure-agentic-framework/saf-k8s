# SAF-K8S-1001-034 — Verify the integrity of retained log batches

```sh
python3 lab.py test SAF-K8S-1001-034 --docker-context desktop-linux
```

In the framework checkout, use `python3 tests/control-lab/lab.py` as the runner.
Kubernetes v1.36.1 runs a Job with separate signer and auditor containers. The
signer puts an ephemeral Ed25519 key in a private memory-backed volume. It writes
the signatures, signed inventory, and public key to a separate volume. The
auditor mounts that volume read-only and has no API credential or private key
mount. Its archive is a ConfigMap containing synthetic retained log batches.

The format-only check accepts a changed event, a truncated batch, and a valid
batch substituted for the original. The auditor rejects all three with the
same trusted signature and reports a batch listed in the signed inventory as
missing. Both original batches verify. The raw evidence includes exact archive
bytes, SHA-256 digests, the inventory, the sample signatures, and the public key.
The private signing key is never logged or retained.

The [pinned SAF-K8S row](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-1001-034.md)
allows cryptographic verification as one way to protect retained log evidence.
[OpenSSL 3.3 pkeyutl](https://docs.openssl.org/3.3/man1/openssl-pkeyutl/#ed25519-and-ed448-algorithms)
documents Ed25519 signing and verification over the exact file bytes.
[Kubernetes v1.36 ConfigMaps](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/configmap/)
document the mounted archive fixture.

The fixture establishes integrity detection for a known inventory. Production
checks still need an approved verification key held independently of the
backend, an authenticated inventory or checkpoint with coverage across batches,
actual log ingestion and backend support, alert routing, and object-lock
configuration where that alternative is used.
