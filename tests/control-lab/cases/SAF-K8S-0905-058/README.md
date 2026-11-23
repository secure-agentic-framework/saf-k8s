# SAF-K8S-0905-058 — Re-sign approved external models before deployment

    python3 tests/control-lab/lab.py test SAF-K8S-0905-058 --docker-context desktop-linux

The fixture uploads the exact synthetic model to a case-owned OCI registry. Independent OpenSSL signer Jobs represent the publisher and the organization, using distinct temporary keys. The organization signer requires recorded approval. A separate verifier checks both signatures against their trusted keys and checks that the incorrect key and a changed payload fail verification.

Kubernetes admission consumes the immutable promotion record, which binds model bytes, OCI manifest, signer and signature. It denies the publisher-only declaration and admits the organization-signed declaration. The admitted fixture Pod fetches and verifies the exact registry artifact.

The host needs OpenSSL. Verify production key custody, deployed approval identities, registry write controls, and workloads outside the reviewed fixture separately.

- [OpenSSL 3.3 signatures](https://docs.openssl.org/3.3/man1/openssl-dgst/)
- [Kubernetes 1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [OCI Distribution v1.1.1](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md)
