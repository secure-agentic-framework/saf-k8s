# SAF-K8S-0402-004 workload identity attribute integrity

Run `python3 tests/control-lab/lab.py test SAF-K8S-0402-004 --docker-context desktop-linux`
from the framework root.

The case grants a synthetic registrar update permission on one ServiceAccount
and one namespace. It proves the workload identity's RBAC denial, then
enforces two approved synthetic metadata values from a typed registry.
The policy scope uses the named namespace and ServiceAccount. An ordinary
namespace metadata change leaves the ServiceAccount guard in effect.
Unapproved updates and removal are denied. The approved value is persisted
and read back. The API server's RequestResponse audit captures matching
approval and denial entries for both targets and excludes Secret and token
resources. No cloud credential or projected token is created.

Deployed federation behavior, projected audiences, approval governance and
audit retention remain separate verification work.

- [Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
