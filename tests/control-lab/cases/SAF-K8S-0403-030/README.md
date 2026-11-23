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
