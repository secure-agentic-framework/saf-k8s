# SAF-K8S-0905-047 — Generate attestations for training and build steps

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-047 --docker-context desktop-linux` from the framework checkout. The host verifier uses OpenSSL.

Restricted training and packaging Jobs report the exact inputs and emit deterministic synthetic model, intermediate, package, and provenance outputs. An attestor Job generates separate in-toto Statement v1 payloads with build provenance predicates and signs DSSE pre-authentication encodings with an ephemeral key held in memory. The independent verifier authenticates the envelope signatures and recomputes the expected material and subject digests. The resulting envelopes are attached to a package in the case-owned Distribution registry through the OCI digest-derived referrers tag, then fetched by digest and compared to the verified bytes.

This verifies the fixture workflow and formats. Verify a deployed builder's authenticated identity, key custody, full workflow coverage, OCI retention and production consumer integration in the target environment.

- [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
- [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
- [SLSA build provenance format](https://slsa.dev/spec/v1.2/build-provenance)
- [OCI Distribution v1.1.1](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md)
