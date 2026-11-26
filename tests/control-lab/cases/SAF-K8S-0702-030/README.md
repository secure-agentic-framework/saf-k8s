# SAF-K8S-0702-030 — Enforce classification changes during promotion

Run the disposable Kubernetes reference from the lab checkout.

```sh
python3 lab.py test SAF-K8S-0702-030 --docker-context desktop-linux
```

From the framework checkout, invoke `python3 tests/control-lab/lab.py`.
An owned Job uses a versioned promotion policy and explicitly scoped
Kubernetes permissions to update synthetic artifact metadata. The case
checks exact label and decision read-back on the target. Promotion lifts
the classification when policy requires it, preserves equal and already
higher classifications, and leaves unknown-policy records unchanged.
The source classification stays unchanged.

Independent fixture identities exercise an unapproved target write and a
policy write by the promotion identity. Native API authorization refuses
both requests. The independently read resource versions, labels and data
stay unchanged.

## Verify adopted classification

1. Inventory each governed artifact, source and target identity, metadata
   owner, target environment and promotion process. Record the independent
   classification authority, versioned policy digest and approved writer.
2. Compare uplift, equal, already higher and unresolved targets through the
   actual promotion route using approved inert artifacts. Verify any policy
   denial stops downstream use. Retain source and target classification,
   exact artifact identity, policy revision and persisted decision.
3. Verify deployment identity and permissions for the actual promotion
   service. Compare authorized writes, unauthorized target and policy writes,
   and concurrent approval or metadata changes. Confirm what the consuming
   admission or deployment service sees after each decision.
   [SAF-K8S-0702-031 demonstrates independent admission on validated classification](https://github.com/secure-agentic-framework/saf-k8s/blob/dd89c426972b672acd34863dfccd404f8c78f171/tests/control-lab/cases/SAF-K8S-0702-031/README.md).
4. Retain the actual registry and metadata evidence, decision, reviewer
   scope and authorized exception process. Repeat after any applicable
   policy or promotion pipeline change.

[Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/).
