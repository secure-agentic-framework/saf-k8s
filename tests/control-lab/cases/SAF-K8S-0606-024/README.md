# SAF-K8S-0606-024 — Protect promotion of Kubernetes policy code

```sh
python3 lab.py test SAF-K8S-0606-024 --docker-context desktop-linux
```

In the framework checkout, use `python3 tests/control-lab/lab.py` as the runner.
The fixture uses Git on the runner host and the Kubernetes v1.36.1 API on a
disposable Kind cluster. Two local bare repositories start with the same
commit. The unprotected repository accepts the candidate. A Git pre-receive
hook on the protected repository rejects the identical candidate because the
tree differs from the independently approved tree. A fast-forward to the
approved tree succeeds. The maintainer fixtures define the expected tree. The
hook represents the enforcement step after approval.

The runner reads the exact files from the protected ref. Kubernetes RBAC
denies promotion by the editor identity. The promoter applies the approved
ValidatingAdmissionPolicy and binding. An otherwise authorized native Role
create that worked before promotion is rejected by CEL after promotion. The
Role that declares read-only Pod access is accepted and read back. No fixture
Role is bound to a subject and the test never reads Secret data.

The passing receipt covers this approved Git tree and one scoped Role policy.
It leaves organization-wide approver identities, key and approval lifecycle,
external Git hosting, network policy, Pod Security Admission, and other
policy families for production verification. Raw evidence includes Git ref
outcomes, exact promoted file hashes, API responses, and the live Policy and
Binding objects.

References include [the pinned control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0606-024.md),
[Git pre-receive hooks](https://git-scm.com/docs/githooks#pre-receive),
[Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/),
and [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/).
