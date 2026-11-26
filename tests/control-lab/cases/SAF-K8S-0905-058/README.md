# SAF-K8S-0905-058 Organization signing after model approval

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-058 --docker-context desktop-linux` from the framework checkout.

The fixture checks external publisher evidence and the approved digest before the organization signs and publishes the inert model to its case-owned OCI registry. A separate verifier retrieves the approved bytes by digest. It loads the organization public key from an immutable trust ConfigMap and compares the expected fingerprint. It accepts the organization signature and refuses both the scoped publisher-key comparison and changed model bytes.

The case uses disposable signing identities, fixed public bytes and separately supplied fixture trust. Verify the operational authority and custody for the organization’s actual signing identities.

## Verify an adopting implementation

1. Inventory the intake and distribution paths. Bind independent approval and external provenance evidence to the exact immutable digest. Verify the organization signer can issue signatures only for their approved scope.
2. Sign and publish under the governed organization identity. Independently read the promoted artifact and signature or attestation from the actual registry. Match the applicable artifact digest, release and approval record.
3. Supply downstream trust through an independently governed identity or key policy. Observe accepted organization signatures and test refusals for altered bytes, unapproved signers and revoked or retired keys through each actual relying boundary.
4. Record the approval, original source and exact digests, signer and trust version, registry identity, verifier results, rotation and revocation behavior, and retained evidence. Confirm the intake and deployment integrations apply the checks to all governed paths.

- [OpenSSL signatures](https://docs.openssl.org/3.3/man1/openssl-dgst/)
- [OCI Distribution Specification v1.1.1](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md)
