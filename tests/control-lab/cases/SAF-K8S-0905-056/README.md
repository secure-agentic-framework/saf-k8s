# SAF-K8S-0905-056 — Verify publisher identity and release provenance

    python3 tests/control-lab/lab.py test SAF-K8S-0905-056 --docker-context desktop-linux

The runner creates a local fixture Git commit and an OpenSSL-signed release binding source, publisher, commit and the hashes of the model and its card. A restricted Kubernetes Job checks an out-of-band public key and the required identifying data before the controller records approval. It rejects the same unsigned release that passed before verification, a signature from a different valid key, a signed release with inconsistent publisher metadata, and changes to the model or card.

The host needs Git and OpenSSL. Both keys and all artifact identities are generated for this run. Verify production publisher identity, trust-root rotation, external metadata coverage and review retention separately.

- [OpenSSL 3.3 signatures](https://docs.openssl.org/3.3/man1/openssl-dgst/)
- [Sigstore blob signing and identity](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/)

## Verify an adopting implementation

1. Inventory each external model source and define canonical identifiers for publisher, repository/source, release or commit, artifact, model card, and applicable signature/attestation formats. Preserve the original source reference and retrieval timestamp.
2. Obtain approved publisher identities and trust roots through a channel independent of the artifact and its metadata. Record the authority, key fingerprint or certificate identity, validity, approval, and the authorized model/repository scope. A public key embedded beside a model is not an independent trust anchor.
3. Define a per-source metadata policy. Mark each field required, optional, unavailable, or not applicable. Treat absent signature/provenance as “not verified”; hold or reject where the required field is absent. Only allow an exception through a named reviewer, reason, expiry, and durable approval record. Do not silently translate missing provenance into verified provenance.
4. Verify signatures/attestations against the approved identity, bind the signed source, publisher, commit/release and artifact digest to the retrieved bytes, and verify the card or associated metadata under the same policy. For keyless signatures, validate the claimed identity and issuer against the organization's approved policy, not merely cryptographic validity.
5. Before internal approval, retain a decision record containing artifact digest, source/release identifiers, signer identity and trust-root version, verification result, missing-field dispositions, reviewer/exception, and timestamp. Protect it against unauthorized change and link it to the approved registry object.
6. Define owner, cadence, key/certificate rotation and revocation handling, re-verification triggers, and inventory coverage. Verify an actual allowed release and expected denials for an unknown signer, missing required signature, mismatched publisher/source/release, changed bytes, expired/revoked identity, and an out-of-scope repository. Capture sanitized records without retaining private keys or model contents in logs.
