# SAF-K8S-0906-007 — Verify stage inputs, outputs and producer identities

Run `python3 tests/control-lab/lab.py test SAF-K8S-0906-007 --docker-context desktop-linux` from the framework checkout.

The four grouped checks run two deterministic transformations of synthetic input. Two restricted Jobs use separate projected identities to create governed stage records through the actual Kubernetes API. Native admission validates the producer, exact parent digest, transformation version and output digest. Changed bytes, stale lineage or version and an alternate identity with an otherwise correct request are refused. Authorized named reads confirm the exact approved records are unchanged. The second Job writes the approved artifact after admission and an independent consumer verifies the bytes. A repeated transformation produces matching output.

## Verify adopted stages

1. Inventory each actual stage and downstream entry point. Record the identity issuer and producer, approved version and trusted policy, source input identifiers, output artifacts and governance authority.
2. Compare real accepted data to controlled mismatches in producer, parent input, transformation version and exact output. Verify each effective gate allows only authorized records and releases and leaves prior approvals unchanged after denial.
3. Test independent reruns for deterministic transforms. For variable outputs, validate authenticated provenance and approved invariants, including exception, retry and recovery behavior.
4. Read back the actual downstream artifact and verify its exact digest, parent lineage and producer against the approved record. Preserve protected receipt and policy identifiers and investigate missing paths.

- [Kubernetes ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
