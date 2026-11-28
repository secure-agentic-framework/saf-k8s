# SAF-K8S-0804-005 modeled policy and software recipient binding

The original three checks remain unchanged: the fixture gates a Kubernetes RoleBinding on modeled appraisal fields, verifies the intended public marker read, and confirms revocation denies later reads.

An additive in-cluster reference release agent validates an immutable synthetic appraisal/request tuple (subject, resource, recipient, recipient public-key digest, ciphertext digest, and time window). On a match it creates one immutable record containing only ciphertext encrypted to the ephemeral intended recipient public key. Two wrong-recipient Jobs must complete successfully with a structured denial naming the recipient check, and their output-record lookups must return exact NotFound. The matching record is checked for immutable status, object identity, exact data fields, and independently recomputed ciphertext digest. The host verifies the exact inert marker decrypts with the matching ephemeral private key; the second fixture key must fail with a recognized OAEP decoding error. Private keys exist only in a mode-0600 temporary directory; they are never mounted into the cluster, passed as arguments, logged, or retained in evidence. Evidence stores booleans and SHA-256 identifiers only.

This is software relying-party behavior using a test public key. It does not demonstrate TEE measurement, signed attestation authenticity, hardware isolation, cloud KMS policy, provider key custody, production recipient identity, key lifecycle, or external broker behavior. The in-cluster service account can create ConfigMaps in this isolated fixture namespace; the example does not claim an admission-enforced production release policy. Those provider and deployment facts remain adoption evidence.

Two independent Kind v1.36.1 runs passed all five checks, including the
signed recipient check. The fixture uses the pinned Python image and an
ephemeral verifier key. It checks the signed synthetic result against a
separate immutable ConfigMap containing the public trust root. Hardware
evidence remains outside this fixture. [Published replay](https://github.com/secure-agentic-framework/saf-k8s/commit/3e64e729dec0a385e12fa738f4fb055a6ccfce6f).


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
