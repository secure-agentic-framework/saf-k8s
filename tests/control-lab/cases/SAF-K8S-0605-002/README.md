# Verify Kyverno admission policies

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0605-002 --docker-context desktop-linux
```

The pinned Kyverno install tests a namespaced ValidatingPolicy in Audit and Deny, scoped mutation, generation of a selected ConfigMap, and image validation against an approved signer and required attestation. Independent comparators cover excluded namespaces, approved input, a missing attestation and a different signer. The case compares the older Policy form with the selected CEL APIs.

For adoption, inventory the installed chart, controller and API versions, required policy types, and effective namespace and resource selectors. Record owners, policy revision, approved exceptions and source-controlled changes. In an approved rollout ring, compare actual Audit findings with later Deny decisions, including allowed, refused and excluded requests. Verify effective mutation and generated-resource lifecycle. Keep the configured secure defaults documented for administrators.

Check the actual registry, artifact subject, signing trust and attestation criteria. Reconcile running workloads with admission coverage and verify trust rotation. For a defined known failure state, check webhook scope and failure policy, choose the expected API behavior and retained state, and verify both a failure observation and recovery on an authorized test path. Preserve the version, exact decision and exception evidence.

[Kyverno policy types](https://kyverno.io/docs/policy-types/) · [Kyverno v1.20.0](https://github.com/kyverno/kyverno/tree/v1.20.0) · [Separate Kyverno webhook failure reference](https://github.com/secure-agentic-framework/saf-k8s/blob/verified-control-tests/tests/control-lab/verified/SAF-K8S-0603-014.json)
