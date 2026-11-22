# SAF-K8S-0907-007 — Namespace-scoped model release

With the SAF-K8S runner, execute:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0907-007 --docker-context desktop-linux
```

The case creates two namespaces in disposable Kubernetes v1.36.1. The
fixture ServiceAccount has Deployment create access in the release
namespace and read access to its one ConfigMap promotion record. The API
confirms the authenticated username from the account's short-lived token.
The token stays in a private temporary kubeconfig for the case.

The API accepts a server-side dry run with an unapproved promotion reference
before the admission policy is in place. A native ValidatingAdmissionPolicy
then rejects the identical dry run, accepts the approved zero-replica
Deployment, and separately denies the wrong model ID and image digest.
Kubernetes RBAC denies the same account both staging Deployment creation
and modification of the promotion record.

The lab exercises API authorization and admission with inert image
references. Registry pull authorization, provenance of a promotion
decision, and deployed namespace coverage require separate evidence.
[Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/),
[ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/).
