# SAF-K8S-0304-006 — Host volume admission

Run from the SAF-K8S framework root on a disposable Kind cluster.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0304-006 --docker-context desktop-linux
```

The case sends the same inert hostPath request before and after applying
Pod Security Admission Baseline v1.36 to the fixture namespace. The native
hostPath denial is matched and an ordinary `emptyDir` request is admitted.

In a second fixture namespace, a ValidatingAdmissionPolicy matches a
synthetic approval record to the exact requester, namespace, workload name,
approval identifier and read-only mount. The named approval admits the
matching dry-run. Missing approval, a different path, a writable mount,
another eligible request identity and another workload name are denied.
The sample opts out of ServiceAccount token volume injection to keep the
approved Pod's volume set exact. The policy itself requires server dry-run.
The test finishes by confirming neither namespace contains a Pod.

## Verify your implementation

1. Inventory the namespaces in scope and the effective default admission
   settings. In an approved disposable namespace, compare a hostPath request
   with an ordinary `emptyDir` request. Keep the versioned policy and exact
   admission results.
2. Use separate scoped policy for approved infrastructure exceptions. Record
   the owner, authorization, identity, exact workload, path, mount mode,
   compensating controls and expiry. Verify absent, mismatched and expired
   approvals fail in the applicable process. Baseline PSA provides default
   denial. The case demonstrates approval removal. The time field in its
   sample record is informational.
3. Verify the actual approved workload's access in authorized representative
   staging. Collect audit events for admitted and denied exceptions and
   link those events to the approval. The case exercises admission only.
   It uses no filesystem mount or workload runtime test.

- [Kubernetes v1.36 Pod Security Standards](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes v1.36 Validating Admission Policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes v1.36 volumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/volumes/)
