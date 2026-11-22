# SAF-K8S-0606-033 — Git-only production deployment path enforcement

Runnable control-lab case for the catalog entry at
[`133a8698a45e2b335b51728bf4c62f7bda98d15f`](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0606-033.md).

Run from the SAF-K8S framework checkout.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0606-033 --docker-context desktop-linux
```

This case uses the framework runner's Kubernetes v1.36.1 Kind node.
It installs Argo CD v3.6.1 from its pinned upstream release manifest and checks
its checksum before use. It creates a case-owned `prod-fixture` namespace
labelled for the policy and verifies the following.

1. `saf-operator` cannot create, update, patch, or delete a Deployment there by
   the effective RBAC rules.
2. Before admission enforcement is enabled, a separate
   `saf-out-of-band-probe` ServiceAccount can create an inert Deployment using
   server dry-run. After the policy is enabled, the identical request receives
   the explicit ValidatingAdmissionPolicy denial.
3. Argo CD's running application controller reads a deterministic local Git
   fixture and syncs the approved Deployment under its actual
   `system:serviceaccount:argocd:argocd-application-controller` identity.

The probe SA exists only to show the policy response independently of RBAC's
earlier authorization gate. It has a narrowly scoped temporary Role only in
the disposable namespace and does not model a normal production permission
set. Both SA tokens are requested through Kubernetes TokenRequest with a short
lifetime, used through private temporary kubeconfigs, never written to evidence,
and removed with the runner's temporary directory. The approved workload is an
inert, single-replica BusyBox sleep Deployment pinned by digest.

This establishes the mechanism only for Deployments, namespace `prod-fixture`,
and this Argo CD version/configuration. It does not establish coverage of other
resource kinds, other namespaces or clusters, all Git change approvals, branch
protection, Git identity provenance, controller credential isolation, or human
operating procedures. The Argo controller identity is an allowlisted principal;
this test does not prove that possession of that identity is itself constrained
to Git-derived requests outside the controller process.

Emergency governance remains separately scoped by SAF-K8S-0606-034. No
impersonation, break-glass role, or admission bypass is implemented here.

## Primary references

- [Pinned original SAF-K8S-0606-033 control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0606-033.md)
- [Kubernetes v1.36 RBAC authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes v1.36 authorization and admission ordering](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authorization/)
- [Kubernetes v1.36 Validating Admission Policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes v1.36 ServiceAccount TokenRequest](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
- [Argo CD v3.6.1 release manifest](https://raw.githubusercontent.com/argoproj/argo-cd/v3.6.1/manifests/install.yaml)
- [Argo CD v3.6.1 auto-sync documentation](https://argo-cd.readthedocs.io/en/release-3.6/user-guide/auto_sync/)
