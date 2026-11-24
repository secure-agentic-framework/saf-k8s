# SAF-K8S-0304-006 — Host volume admission and approved exceptions

Run from the SAF-K8S framework root on a disposable Kind cluster.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0304-006 --docker-context desktop-linux
```

A synthetic hostPath request is accepted before the fixture namespace has
Pod Security Admission Baseline. Baseline v1.36 denies the same server dry
run and admits the ordinary `emptyDir` request.

A separate namespace uses a ValidatingAdmissionPolicy with an exact
approval record. The policy checks the approved requester, namespace,
workload name, approval ID, exact marker path and read-only mount. It also
requires non-root operation, removal of capabilities and token automount
disabled. Server dry-runs show that wrong or missing approvals, a writable
mount and a different identity or workload are denied.

The runner supplies one read-only marker file to the disposable node from
its temporary directory. Only the exact approved workload is persisted.
The unprivileged container confirms the mount flags and reads the marker.
The case removes that workload, advances a fixture clock and revokes the
expired approval. The same exact request is then denied.

The case also retains Metadata-level API audit evidence for the owned
permitted and denied exception decisions. The evidence includes actor,
namespace, target, response code and dry-run status. Request and response
objects are absent. The test clock demonstrates the approval lifecycle.
Real deployments need a trusted clock and an accountable reconciliation
process.

## Verify your implementation

- Confirm effective default denial across the applicable workload
  namespaces and pin the admission policy version.
- Record the exact approved requester, service identity, workload, path,
  read-only mode, owner, compensating controls and expiry. Check that the
  reconciler removes expired approvals and the missing-approval policy
  fails closed. Review any already running workload according to the
  deployment's response policy.
- In authorized representative staging, verify one approved workload and
  use server dry-runs for disallowed variants. Retain the native admission
  results, the actual mount and read evidence, and attributable audit
  events. Check downstream severity, delivery and retention separately.

- [Kubernetes v1.36 Pod Security Standards](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes v1.36 Validating Admission Policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes v1.36 hostPath](https://v1-36.docs.kubernetes.io/docs/concepts/storage/volumes/#hostpath)
- [Kubernetes v1.36 auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
