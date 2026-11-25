# SAF-K8S-0403-030 Secret environment exception review

Run by ID on fresh Kind. An exception registry entry names one fixture
deployer and workload, includes approval and re-review data, and
requires a read-only root filesystem. The live admission decision
validates the current entry and the approved Pod consumes a harmless
public marker. Reconciliation at a controlled later review time removes
authorization, while normal non-Secret admission still works.

The fixture uses ConfigMap state and an explicit reconciliation step.
Evaluate production registry completeness, review automation, applicable
injection paths, approval authority, and compensating controls separately.

- [Kubernetes Secret consumption](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/secret/)
- [Kubernetes parameterized admission](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)

From the SAF-K8S repository root, run `python3 tests/control-lab/lab.py test SAF-K8S-0403-030 --docker-context desktop-linux`.

## Adopter verification

Inventory environment Secret use across supported workloads, controller templates and approved delivery routes. Check that an exception record identifies a verifiable approver, owner, rationale, exact resources and compensating settings, and review deadline. Exercise a permitted approved change and an equivalent unapproved or expired change. Verify what happens to existing workloads and new requests when review expires. Retain exact policy, immutable record references, effective compensation and remediation owner.
