# SAF-K8S-0704-015 — effective external identity and authorization

From the SAF-K8S checkout:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0704-015 --docker-context desktop-linux
```

Two fresh Kind v1.36.1 runs verify seven cases. The original API checks demonstrate named-resource Kubernetes RBAC using controlled subject attributes. The native extension then configures a loopback fixture issuer, an exact JWT audience, and a prefixed group mapping. A separate binding grants only the named ConfigMap read.

The API initially rejects the fixture issuer. Once configured, it permits the approved group and marker, denies the unrelated group and object, and rejects the wrong audience. Removing the exact OIDC binding revokes the read while the API still authenticates the subject. Restoring the original API configuration brings the endpoint back to Ready and the fixture issuer is rejected again. Results retain sanitized decisions and omit credential values.

## Adopter verification

1. Inventory applicable human, automation and workload principals, group sources, managed access modes and exceptions. Record effective authentication paths and the authority that resolves each subject and group.
2. Reconcile the inventory to the actual issuer, audiences, claim mappings, Kubernetes bindings and provider or other authorizer policies. Record the ordering or combination of applicable authorizers and the effective action/resource scope.
3. Exercise approved low-impact allowed and denied requests with representative identities over each adopted path. Verify both the subject attribution and resulting authorization decision, including independent paths and unintended privileges.
4. Verify each applicable grant withdrawal or identity deactivation, preserve independent required grants and review provider-side propagation. Retain scope, versions, timestamps, policy snapshots, sanitized outcomes and repeat-review ownership.

[Kubernetes v1.36 structured authentication](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authentication/) · [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
