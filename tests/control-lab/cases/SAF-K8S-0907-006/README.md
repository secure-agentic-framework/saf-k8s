# SAF-K8S-0907-006

Run `python3 tests/control-lab/lab.py test SAF-K8S-0907-006` from the repository root. The baseline and approved readers use the actual Kubernetes API and a local persistent volume. Native admission denies an out-of-scope fresh claim reference. API grants and filesystem groups preserve authorized reads and deny the opposite fixture files and API objects.

Verify control over workload identity selection, actual storage and feature-store permissions, and cloud identity and object-store policy separately.

[Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/) · [ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)

## Verify an adopting implementation

Inspect deployed ServiceAccount selection, admission policy, PVC/backend
permissions and filesystem group ownership. Use approved and out-of-scope
fixture files to verify authorized access and denial at both Kubernetes API
and storage layers. Cover cloud object-store identity separately. The case
exercises real native API/RBAC/admission and local PV access only.
