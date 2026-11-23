# SAF-K8S-0905-056 — Verify publisher identity and release provenance

    python3 tests/control-lab/lab.py test SAF-K8S-0905-056 --docker-context desktop-linux

The runner creates a local fixture Git commit and an OpenSSL-signed release binding source, publisher, commit and the hashes of the model and its card. A restricted Kubernetes Job checks an out-of-band public key and the required identifying data before the controller records approval. It rejects the same unsigned release that passed before verification, a signature from a different valid key, a signed release with inconsistent publisher metadata, and changes to the model or card.

The host needs Git and OpenSSL. Both keys and all artifact identities are generated for this run. Verify production publisher identity, trust-root rotation, external metadata coverage and review retention separately.

- [OpenSSL 3.3 signatures](https://docs.openssl.org/3.3/man1/openssl-dgst/)
- [Sigstore blob signing and identity](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/)
