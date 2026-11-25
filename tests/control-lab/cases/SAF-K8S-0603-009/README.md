# SAF-K8S-0603-009 — Build provenance generation

Run `python3 lab.py test SAF-K8S-0603-009` from the control lab.

A temporary pinned BuildKit daemon builds a real single-platform OCI image
from a pinned BusyBox input. This version exports an in-toto Statement v0.1
with a SLSA Provenance v1 predicate. Record the versions independently.
The test checks that BuildKit's subject is the exact exported image manifest,
then publishes that image to a disposable TLS registry. Before the signed
attestation is published, verification for the same digest must fail.

Cosign signs the BuildKit-generated predicate using an ephemeral fixture key.
The test fetches the signed attestation and compares the verified predicate
and subject with BuildKit's output. A Kind Pod then runs the exact digest and
prints the file produced by the build. A structured receipt retains the
generated statement and the verified manifest digest.

Production builder identity and isolation, vendor attestations, image-index
and platform digest coverage, and any claimed SLSA level require evidence
from the real CI and promotion system.

## Adopter verification

1. Map each CI trust root, signer identity, builder isolation boundary and required source/build inputs to the actual promoted artifacts.
2. For every platform image manifest and index, verify the attestation subject digest matches the promoted digest and the intended consumer can retrieve and authenticate the signed predicate.
3. Review retention, registry replication/copy behavior and vendor-built images separately. record exceptions and unsupported source fields.
4. Claim a SLSA level only when the real builder and process meet that level's independent requirements. the predicate format alone is insufficient.
