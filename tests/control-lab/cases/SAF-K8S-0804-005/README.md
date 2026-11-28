# SAF-K8S-0804-005 modeled policy and software recipient binding

The original three checks remain unchanged: the fixture gates a Kubernetes RoleBinding on modeled appraisal fields, verifies the intended public marker read, and confirms revocation denies later reads.

An additive in-cluster reference release agent validates an immutable synthetic appraisal/request tuple (subject, resource, recipient, recipient public-key digest, ciphertext digest, and time window). On a match it creates one immutable record containing only ciphertext encrypted to the ephemeral intended recipient public key. Two wrong-recipient Jobs must complete successfully with a structured denial naming the recipient check, and their output-record lookups must return exact NotFound. The matching record is checked for immutable status, object identity, exact data fields, and independently recomputed ciphertext digest. The host verifies the exact inert marker decrypts with the matching ephemeral private key; the second fixture key must fail with a recognized OAEP decoding error. Private keys exist only in a mode-0600 temporary directory; they are never mounted into the cluster, passed as arguments, logged, or retained in evidence. Evidence stores booleans and SHA-256 identifiers only.

The software release fixture uses a test public key and a service account that can create ConfigMaps in the isolated fixture namespace. Live enclave measurements, hardware isolation, KMS policy and custody, production recipient identity, key lifecycle, and external broker behavior remain adoption evidence.

Two independent Kind v1.36.1 runs passed all five checks, including the
signed recipient check. The fixture uses the pinned Python image and an
ephemeral verifier key. It checks the signed synthetic result against a
separate immutable ConfigMap containing the public trust root. Live enclave evidence remains a deployment requirement. [Published replay](https://github.com/secure-agentic-framework/saf-k8s/commit/3e64e729dec0a385e12fa738f4fb055a6ccfce6f).


## Signed verifier-result supplement

The relying-party Job verifies a detached signature over the exact result bytes,
then checks verifier identity, approval status, subject, request reference, resource,
recipient and public-key digest, per-case challenge, live validity interval, and
ciphertext digest before it can create a release record. Validly signed
wrong-request and wrong-challenge results, an expired signed result, and a result
signed by a different fixture key must be denied with exact NotFound readback.
The positive path releases only the existing inert marker encrypted to the
intended recipient; the host decrypts it and compares exact bytes without
retaining plaintext or private keys. Challenge matching here is tuple binding,
not a distributed replay-prevention claim.

This is a synthetic verifier-to-relying-party reference, not a RATS-conformant
attestation protocol or evidence of hardware appraisal. IETF [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334/)
distinguishes verifier evidence appraisal from the relying party's evaluation of
attestation results; this fixture models only a small signed-result trust boundary.
Verify the provider verifier, supported evidence format, trust anchors, freshness
policy, recipient identity, KMS/broker authorization, audit, and revocation behavior
in the adopted platform.

## Archived AWS Nitro release decisions

The case also verifies two AWS-published 2023 attestation documents in a
Kind Job with a default-deny NetworkPolicy. The runner fetches an exact source revision and
checks each input digest. The verifier validates the certificate paths at
the signed issuance times, anchors them to the separately downloaded and
fingerprint-pinned AWS Nitro root, and checks the ES384 signatures over the
original COSE bytes. It authenticates the sample with zero PCR0–PCR2 and the
sample with the expected nonzero PCR0–PCR2. Separate signature and signed
payload changes must fail verification.

The current grant policy compares the workload measurements, current
certificate validity, evidence age, fresh request challenge and recipient
key. Both historical samples are stale and omit the challenge and
recipient fields needed for release. The lab applies the observed decisions
to the same Kubernetes marker grant used in the modeled release test. An
authenticity-only comparator can grant access to that inert marker. The
current policy keeps the RoleBinding absent and a live API read forbidden.

The Job and the marker gate retain normalized evidence in
`nitro-archived-release.json`. Run the usual case-by-ID command with Docker,
Kind, kubectl, curl and Go. The first build needs access to the public AWS
sample sources and the checksummed Go module dependencies. Live Nitro
challenge issuance, private recipient possession, AWS KMS policy and
release, and deployed key lifecycle require separate evidence.

- [AWS-published sample revision](https://github.com/aws-samples/aws-iot-validate-enclave-attestation/tree/14e13acb5d896a897e11c5b3e71caf01412611c8)
- [AWS Nitro format and root verification](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)
- [AWS KMS attested calls](https://docs.aws.amazon.com/kms/latest/developerguide/attested-calls.html)
