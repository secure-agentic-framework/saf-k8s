# SAF-K8S-0603-008 — Build materials and artifact attestations

```sh
python3 lab.py test SAF-K8S-0603-008 --docker-context desktop-linux
```

NIST SP 800-204D §5.1.1 describes materials and artifact evidence and calls for cryptographically signed build evidence. The corrected SAF control keeps its own requirement to sign the two categories independently. [NIST SP 800-204D](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204D.pdf#page=25).

A real Kubernetes builder Job reads two mounted inert fixtures, normalizes the source into an intermediate, and concatenates the intermediate and dependency to create a final artifact. The runner checks the actual consumed and produced bytes and all four digests. It signs separate in-toto Statement v1 payloads with distinct ephemeral local keys, using the DSSE pre-authentication encoding. A separate Kubernetes Job checks both signatures, the expected statement contents, and the actual intermediate and final product digests. [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md), [DSSE protocol](https://github.com/dsse-lf/dsse/blob/master/protocol.md).

The verifier accepts the complete evidence and rejects a statement from the same trusted fixture signer that omits the consumed dependency. The original and corrected catalog each passed all ten checks in separate Kubernetes v1.36.1 Kind clusters and completed cleanup. The lab receipts are `evidence/SAF-K8S-0603-008/20261122T094728Z-dca01639/result.json` and `evidence/SAF-K8S-0603-008/20261122T094857Z-95a12416/result.json`.

This case covers the two observed fixture inputs and two fixture products. Production build-event collection, signer identity and protection, evidence storage, complete pipeline coverage, and downstream consumer policy remain separate evidence obligations.

## Verify an adopting implementation

For each production pipeline, capture the inputs actually
read (including remote contexts, lockfiles, generated intermediates, and
toolchain), then bind them and the final subject to authenticated attestations.
Prove the attestor identity is protected from developer-controlled build
steps; retain signer rotation, evidence storage, and consumer policy. Exercise
an omitted material and a changed subject through the real release verifier.
