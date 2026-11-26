# SAF-K8S-0606-024 — Protect promotion of Kubernetes policy code

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0606-024 --docker-context desktop-linux
```

Two local bare Git repositories start from the same commit. The open repository accepts the initial candidate. The protected repository rejects changes to each of five policy files independently and advances only to the approved tree. The runner checks each promoted file's exact bytes and records its hash. The fixture's pre-receive hook illustrates enforcement after approval.

The editor's Kubernetes identity is denied promotion. One authorized promoter applies the approved ValidatingAdmissionPolicy, binding, empty unbound Role, NetworkPolicy, and warn-only Pod Security Namespace labels. The test confirms the API state and verifies the NetworkPolicy selects no Pods. The admission policy still rejects the case Role that requests Secret reads and admits the approved Role with Pod reads. No fixture Role is bound to a subject.

For deployment, identify each repository, approved revision and managed policy file. Verify the actual change and branch protection with named approvers, the signer or equivalent integrity control, and restrictions on push, merge, workflow and bypass permissions. Follow the approved manifest from the release commit through delivery to the effective API state, including rollback and drift reconciliation. Preserve a rejected unapproved change, the approved release and change record, and permission and API evidence for each governed configuration family. Check who can change effective network, RBAC, admission and Pod Security settings through other routes.

[Git pre-receive hooks](https://git-scm.com/docs/githooks#pre-receive) · [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/) · [Kubernetes v1.36 Pod Security Admission](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-admission/)
