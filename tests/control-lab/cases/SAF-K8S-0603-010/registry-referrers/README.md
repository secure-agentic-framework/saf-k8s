# OCI discovery of a digest-bound SBOM

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0603-010 --docker-context desktop-linux
```

This comparison uses an isolated loopback TLS Distribution 3.0.0 registry,
the two images from the Kubernetes verification and the same signed SBOM. It needs Python
3.9 or later, OpenSSL, and a Docker context backed by a local Unix socket.
Each run removes its registry container, named volume and private keys.

The native referrers endpoint returns HTTP 404 in this registry version.
The OCI 1.1 tag fallback returns zero descriptors for the approved digest
before publication and exactly one afterward. The unrelated digest stays
empty. The reader retrieves the manifest and DSSE envelope by digest,
checks equality to the published bytes and verifies the signature against
the generated public key. The verified CycloneDX 1.6 statement identifies
the approved image's exact digest.

The runner retains protocol statuses, exact subject and artifact digests,
signature verification and cleanup in `registry-referrers.json` alongside
the by-ID result. [OCI 1.1 fallback](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#referrers-tag-schema).
