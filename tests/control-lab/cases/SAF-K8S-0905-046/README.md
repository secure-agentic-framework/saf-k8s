# SAF-K8S-0905-046 — Sign each artifact in a training pipeline

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-046 --docker-context desktop-linux` from the framework checkout.

A restricted training Job fits a line from synthetic input records and builds five distinct artifact files. A separate OpenSSL signer Job creates a disposable signing key in a private memory volume and signs statements binding each artifact name, exact SHA-256 and fixture pipeline identity. A verifier Job gets the approved public key independently of the artifact documents and recomputes the five digests. It rejects missing signatures, an altered model, and valid signatures made over the same statements by a second signer.

This case uses local key-based signing with an explicitly chosen fixture trust root. Verify production key custody and rotation, binding of the trusted key to platform identity, deployers' trust configuration, complete artifact inventory, and the external re-signing workflow separately.

- [Sigstore blob signing](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/)
- [OpenSSL 3.3 digest and signature commands](https://docs.openssl.org/3.3/man1/openssl-dgst/)

## Verify an adopted pipeline

1. Enumerate files from one actual run, match each file to its pipeline stage and release identifier, and compare the inventory against signed statements for exact artifact names and SHA-256 digests. Record any exclusions and who approved them.
2. Verify the managed key or keyless signer subject, issuer, pipeline or workflow identity, and release authorization against identities established independently of the artifact. Inspect key custody, planned rotation and revocation, and confirm the verifier rejects a retired or unrelated identity according to policy.
3. Use an approved artifact and controlled copies to show that the deployed verifier accepts the expected signer and exact bytes, then rejects a missing signature, modified bytes, and a signature from another identity. Record the verifier and trust-policy revisions with the results.
4. If the pipeline imports signed external artifacts, trace one intake to its approved supplier and verification result, the authorized re-signing step, and the new internal trust statement. Run the same rejection checks on controlled intake copies and retain the original and internal evidence references.
5. Record run ID, artifact digests, signer identity and trust-policy revision with the verification results. Test deployment enforcement independently wherever the policy requires it.
