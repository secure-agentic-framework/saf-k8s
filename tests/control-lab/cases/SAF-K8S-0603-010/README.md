# SAF-K8S-0603-010 — SBOM attestation binding to image digests

```sh
python3 lab.py test SAF-K8S-0603-010 --docker-context desktop-linux
```

The case creates two inert OCI image layouts and verifies their manifest, configuration and layer digests. It reads the package metadata from each verified layer, generates a CycloneDX 1.6 SBOM and includes it in an in-toto statement whose subject is the image manifest digest. The same ephemeral RSA key signs each statement using DSSE pre-authentication encoding. [OCI Image Manifest](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md), [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md), [CycloneDX reference](https://cyclonedx.org/docs/1.6/json/).

An independent Kubernetes Job parses the signed statement and recomputes the manifest digest. OpenSSL verifies the signature using the separate trust fixture, then the Job compares the parsed subject to the actual and approved manifest digests. The approved image passes. A valid claim from the same trusted signer for the distinct image verifies cryptographically and fails the approved-subject check.

The live result is `evidence/SAF-K8S-0603-010/20261122T100230Z-da419fde/result.json`. The fixture inventories its own published package-metadata format. General-purpose SBOM completeness, durable registry attachment and referrer lookup, platform coverage, signer governance, and deployment evidence remain separate obligations. [OCI referrers](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#listing-referrers).
