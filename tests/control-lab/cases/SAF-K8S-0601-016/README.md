# SAF-K8S-0601-016 — Approved base image provenance

```sh
python3 lab.py test SAF-K8S-0601-016 --docker-context desktop-linux
```

The case uses a local Docker Buildx builder with OCI export and BuildKit
SLSA v1 provenance support. A local-only build resolves the pinned public
fixture base. The verifier checks the OCI descriptor digests and sizes,
matches the attestation's reference to the selected workload manifest,
and compares the resolved base digest with the allowlist.

A separate synthetic fixture verifies a trusted builder's DSSE signature,
statement type, workload subject digest, and exact approved base material.
It rejects missing or changed provenance and validly signed but unapproved
base material. The static OCI artifact identifies a final image digest,
while its history provides only a self-reported build description. The live
builder output and the signed fixture establish different parts of the
control. The BuildKit attestation emitted for the live build is unsigned.

The run needs OpenSSL and a local Docker builder. It sends no images
to a registry. The live archive and temporary verification inputs are
cleaned up. Production approval workflows, trusted build identities,
registry distribution, signed provenance attached to the actual artifact,
and admission deployment still need verification.

- [OCI image configuration](https://github.com/opencontainers/image-spec/blob/v1.1.1/config.md)
- [Docker BuildKit provenance attestations](https://docs.docker.com/build/metadata/attestations/slsa-provenance/)
- [SLSA Provenance v1.0](https://slsa.dev/spec/v1.0/provenance)

## Adopter verification

1. Inventory deployed builder identities and the approved base catalog,
   including allowed digest updates and exceptions.
2. For each promoted image, resolve the OCI subject digest and retain the
   authenticated provenance, signer identity, and resolved base materials.
3. Exercise the real promotion/admission path with missing provenance, an
   alternate subject, and a signed but unapproved base. Show denial and the
   approved digest succeeding. Keep any unsigned builder output distinct from
   authenticated provenance.

Open child: `saf-lab-0601-016.1`. Native receipt: 9 checks.
