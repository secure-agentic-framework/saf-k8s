# SAF-K8S-0704-017 — Effective cloud-to-cluster authorization

Run from the lab checkout.

```sh
python3 lab.py test SAF-K8S-0704-017 --docker-context desktop-linux
```

From the framework checkout, invoke `python3 tests/control-lab/lab.py`.
The native authorization case evaluates one owned synthetic subject
with two additive RBAC grants. Before remediation the actual API
returns both the intended marker and the extra marker. Removing only
the extra binding preserves the intended permission and produces a
named refusal for the previously extra marker. Independent authorization
reviews compare the exact resource and namespace matrix.

The runner uses the synthetic subject through Kubernetes impersonation
for this authorization check. [SAF-K8S-0704-015 demonstrates native signed OIDC authentication and scoped binding](https://github.com/secure-agentic-framework/saf-k8s/blob/594a58d448dd2d4b331550fb7238ac7f313c66d3/tests/control-lab/cases/SAF-K8S-0704-015/README.md).

## Verify the adopting privilege boundary

1. Identify actual cloud, federated and Kubernetes principals and
   all used identity claims, authorizers, broad or indirect approvals,
   emergency paths and exceptions. Create the approved matrix of
   actions, resources, namespaces and privileged capabilities.
2. Resolve actual provider role assignments and Kubernetes bindings.
   Compare intended decisions with independently authenticated API
   requests for approved and denied ordinary operations. Record source,
   identity, effective scope and each contributing grant.
3. Correct the independently identified contributing grant and repeat
   permitted and denied comparisons. Check alternate group, namespace
   and provider paths, and ensure an unrelated approved user keeps access.
4. Retain the approved exception owner and expiry, observed decisions,
   exact mapping and policy revisions, applicable cleanup and evidence
   for every active authorization path.

[Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/).
