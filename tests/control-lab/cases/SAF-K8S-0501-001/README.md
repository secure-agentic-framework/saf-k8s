# Verify default-deny policies and namespace onboarding

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0501-001 --docker-context desktop-linux
```

The disposable kindnet fixture verifies ingress and egress default denial through distinct allowed and refused TCP comparisons and checks that both listeners remain healthy. A pinned Kyverno generator adds separate namespace-wide ingress and egress policies to two enrolled namespaces. A labelled namespace outside the selected names remains unchanged, late enrollment produces the exact pair, and a deleted policy is restored as a new API object.

For adoption, verify that the installed CNI implements the relevant NetworkPolicy and protocol behavior. Inventory the governed namespaces and approved paths, including system and observability dependencies. Verify selector scope and additive policy interactions before introducing default denial. Stage required DNS and service paths and check how workloads wait for effective isolation on enrollment. Compare permitted and excluded paths from owned test workloads. Review the effective policy controller, reconciliation after controlled drift, and who can change enrollment and exceptions. Record policy and namespace identities, actual observations and the approved policy revision.

[Kubernetes v1.36 NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/) · [Kyverno policy types](https://kyverno.io/docs/policy-types/)
