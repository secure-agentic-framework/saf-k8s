# SAF-K8S-0906-007 — Bind integrity checks to exact transformation stages

Run `python3 tests/control-lab/lab.py test SAF-K8S-0906-007 --docker-context desktop-linux` from the framework checkout.

The four checks execute real synthetic transformations, reject modified input and wrong expected hashes, and verify that the approved output reaches an independent consumer. Kubernetes admission binds two stage records to their exact parent SHA-256, transformation version and output SHA-256. An incorrect parent and an unapproved transformation version are denied and remain absent. The test compares admitted records, repeated workload outputs and the retained downstream artifact.

## Verify adopted stages

1. Inventory each transformation and consuming entry point, its approved producer identity, stage and version, artifact and lineage schema, expected inputs, determinism and documented invariants.
2. Verify the deployed gate authenticates the producer, preserves the exact immutable input and output identities and trusts expected values independently. Compare native decisions for missing metadata, stale or incorrect version, unexpected parent or bytes, and an unapproved producer.
3. For deterministic stages, compare independent exact reruns. For variable outputs, verify the approved provenance and applicable invariants, including exception, failure and retry behavior.
4. Read back the actual downstream artifact, check its reference and digest against the final accepted record, and retain the approved evidence for all effective paths.

- [Kubernetes ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
