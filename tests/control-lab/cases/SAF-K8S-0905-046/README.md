# SAF-K8S-0905-046 — Sign each artifact in a training pipeline

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-046 --docker-context desktop-linux` from the framework checkout.

A restricted training Job fits a line from synthetic input records and builds five distinct artifact files. A separate OpenSSL signer Job creates a disposable signing key in a private memory volume and signs statements binding each artifact name, exact SHA-256 and fixture pipeline identity. A verifier Job gets the approved public key independently of the artifact documents and recomputes the five digests. It rejects missing signatures, an altered model, and valid signatures made over the same statements by a second signer.

This case uses local key-based signing with an explicitly chosen fixture trust root. Verify production key custody and rotation, binding of the trusted key to platform identity, deployers' trust configuration, complete artifact inventory, and the external re-signing workflow separately.

- [Sigstore blob signing](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/)
- [OpenSSL 3.3 digest and signature commands](https://docs.openssl.org/3.3/man1/openssl-dgst/)
