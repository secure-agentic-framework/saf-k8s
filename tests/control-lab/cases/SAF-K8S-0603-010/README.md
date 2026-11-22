# SAF-K8S-0603-010 — SBOM attestation binding to image digests

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0603-010 --docker-context desktop-linux
```

The case creates two inert OCI image layouts and verifies their manifest, configuration and layer digests. It reads the package metadata from each verified layer, generates a CycloneDX 1.6 SBOM and includes it in an in-toto statement whose subject is the image manifest digest. The same ephemeral RSA key signs each statement using DSSE pre-authentication encoding. [OCI Image Manifest](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md), [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md), [CycloneDX reference](https://cyclonedx.org/docs/1.6/json/).

An independent Kubernetes Job parses the signed statement and recomputes the manifest digest. OpenSSL verifies the signature using the separate trust fixture, then the Job compares the parsed subject to the actual and approved manifest digests. The approved image passes. A valid claim from the same trusted signer for the distinct image verifies cryptographically and fails the approved-subject check.

The case inventories its own package-metadata format. It publishes and
independently retrieves the same image and signed SBOM through the local registry.
Production SBOM completeness, signer governance, registry compatibility,
and deployment coverage require separate evidence.
[Registry attachment test](registry-referrers/README.md).
