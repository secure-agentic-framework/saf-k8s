# SAF-K8S-1001-025 — Dual authorization for audit record changes

```sh
python3 lab.py test SAF-K8S-1001-025 --docker-context desktop-linux
```

From the SAF-K8S checkout, run `python3 tests/control-lab/lab.py` with the same arguments. In a fresh Kubernetes v1.36.1 Kind cluster, three fixture Pods authenticate with separate ServiceAccounts. RBAC limits each principal to named synthetic records or approval ledgers. Native ValidatingAdmissionPolicies bind separate update and purge approvals to the exact Kubernetes UID and operation.

The pre-enforcement dry-run requests succeed and the purge object stays present. After the relevant bindings take effect, zero votes or one repeated vote leaves the action denied. Each reviewer can set only its field. Direct operation by a reviewer is denied by RBAC, and votes for one UID leave a decoy UID unauthorized. The approved annotation change preserves the synthetic event. The separately approved purge deletes only its expected record.

For the purge baseline, the probe sends `dryRun: [All]` in the same `DeleteOptions` body as the UID precondition. The case records the returned decisions and the end state without retaining credentials.

The fixture uses Kubernetes-backed synthetic audit records. Production workflow integration, distinct human identities, approval lifecycle, storage-admin boundaries, and other audit lifecycle actions require deployment evidence.

[Kubernetes validating admission](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/) · [Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/) · [v1.36.1 DeleteOptions handling](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/delete.go)

## Adopter verification

1. Inventory every operation that can delete, purge, compact, mutate, or change retention for audit evidence, including automation, cloud consoles, break-glass access, and provider support.
2. Review the effective workflow so two distinct authorized people approve the same record/resource, operation, and bounded request; prohibit self-approval and direct unilateral execution.
3. In a non-production rehearsal, demonstrate that no approval and one approval are denied, repeated/scope-mismatched approvals do not count, and the exact fully approved synthetic action succeeds. Confirm all attempts are independently logged.
4. Retain role separation, workflow configuration, scoped decision results, audit-trail evidence, and exception ownership. Avoid testing deletion of production records.
