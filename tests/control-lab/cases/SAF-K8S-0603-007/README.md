# SAF-K8S-0603-007 — Build environment and process attestations

```sh
python3 lab.py test SAF-K8S-0603-007 --docker-context desktop-linux
```

NIST SP 800-204D §5.1.1 describes contemporaneous environment inventory, build and test tooling as process evidence, and signing through a trusted build component. It treats process collection as best effort. The corrected SAF control attributes the two categories and that qualification to NIST and states independent category signing as SAF policy. [NIST SP 800-204D, pp. 16–17](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204D.pdf#page=25).

The case provisions a fresh Kubernetes v1.36.1 Kind cluster. It defines two independent inert artifacts and constructs an environment and a process Statement v1 payload for each. The subjects carry the SHA-256 of the corresponding artifact bytes. The test signs each payload with a distinct ephemeral local RSA key and the DSSE pre-authentication encoding. Kubernetes Jobs using the digest-pinned OpenSSL image reconstruct the encoding and verify against the fixture public key and expected payload digest. Any private key stays in the host temporary directory. [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md), [DSSE protocol](https://github.com/dsse-lf/dsse/blob/master/protocol.md).

The first pair must verify. Flipping a signature byte must produce the exact verifier rejection marker. A valid signature made by the same trusted fixture signer over a different artifact must pass cryptographic verification and fail the pinned payload comparison. The independent artifact's two claims must then verify for its own subject. Cases use detached signatures and DSSE encoding. Envelope transport, real inventory and transformation capture, audited signer authority, key protection, and actual production consumers require separate evidence.

Results are retained for the original and corrected catalog revisions, along with a separate framework replay. The results contain only deterministic fixture observations. All keys are ephemeral.
