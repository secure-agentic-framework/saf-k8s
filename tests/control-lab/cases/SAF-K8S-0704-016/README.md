# SAF-K8S-0704-016 — Effective entitlement drift and scoped remediation

Run from the lab checkout.

```sh
python3 lab.py test SAF-K8S-0704-016 --docker-context desktop-linux
```

From the framework checkout, invoke `python3 tests/control-lab/lab.py`.
The initial namespaced RoleBinding grants an invented stale group access
and omits the governed approved group. Real API requests independently
observe both effects. A case Job uses the scoped remediation
ServiceAccount to replace subjects on its one named RoleBinding.
Its version-guarded write persists the intended state. The same API
queries verify approved access and loss of stale access. An unrelated
binding remains effective.

An unbound Job cannot modify the governed binding. The authorized
remediation Job cannot modify the unrelated binding or approval policy.
Independent reads verify their stored state after the refusals.

## Verify adopted entitlements

1. Record each actual identity provider and group mapping, cloud
   entitlement, cluster role and namespace, inherited group and
   privileged access path. Resolve the expected entitlement and owner
   from the approved source revision.
2. Compare intended and effective permissions independently. During an
   approved test, verify the authorized and stale identities through the
   actual mapped path. Capture the principal, expected action, scope
   and resulting decision.
3. Restrict the remediator to the authorized changes and record its
   approval, independent policy source, controlled scope and required
   escalation. Confirm unauthorized or out-of-scope attempts preserve
   state. Verify the actual permissions after correction and keep
   unrelated access available.
4. Define review cadence, change triggers, time targets and exception
   expiry. Retain inventory differences, effective before-and-after
   evidence, exact revisions and reviewer ownership.

[Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/).
