# SAF-K8S-0602-001 — Private keyless signing and transparency

Run `python3 lab.py test SAF-K8S-0602-001` from the control lab. The test requires
OpenSSL 3 or later and PyYAML for the checksum-pinned Sigstore test manifests.

A disposable cluster hosts Fulcio, certificate transparency, Rekor,
timestamping and its own TUF mirror. The Kubernetes API issues a short-lived
token with audience `sigstore`. Fulcio accepts the cluster issuer and emits a
signing certificate for the dedicated fixture ServiceAccount. The ephemeral
Cosign cache uses only the private mirror and the bootstrapped fixture root.

The test signs an exact harmless OCI image digest in the private registry and
checks the returned Fulcio certificate, Rekor inclusion proof, timestamp and
configured identity. It challenges the same signature with a different
expected identity and issuer. The release invokes Kubernetes after signature
verification. Production identity policies, admission coverage and provenance
verification need separate evidence.
