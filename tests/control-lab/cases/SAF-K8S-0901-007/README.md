# SAF-K8S-0901-007 — Scope a synthetic AI controller identity

This case exercises the Kubernetes RBAC portion of the pinned control on a
disposable Kind Kubernetes v1.36.1 cluster. It uses a dedicated synthetic
controller ServiceAccount in `saf-0901-007-operator` and a RoleBinding in
`saf-0901-007-workloads`. A short-lived mock probe Pod runs as that account
with its projected token.

Before the RoleBinding exists, direct API `GET` and `PATCH` requests for the
existing mock workload are denied. After binding, the controller can read and
patch only the named ConfigMap `mock-raycluster-spec` in the workloads
namespace. Requests for a sibling ConfigMap, the same named ConfigMap in the
adjacent namespace, list access, Secrets, and cluster-scoped Nodes remain
denied. `kubectl auth can-i` independently checks the same namespace/resource
boundaries. A control-plane read verifies that the permitted patch persisted.

The ConfigMaps are inert synthetic workload descriptors, not Ray/Kubeflow or
other operator custom resources. No real operator, GPU device, third-party
controller, target, vulnerability feed, scanner, or vendor image is installed
or contacted. Both the Kind node and the Python probe image are digest-pinned.
The `registry.example.invalid` image string and all-zero digest in the mock
workload descriptor are reserved inert placeholders; they are never pulled.
Raw evidence records the probe's verified service-account subject, API
operation names, status codes, synthetic marker checks, authorization answers,
and the resulting mock object. It excludes bearer tokens, credentials, Secret
data, and request/response bodies.

## Claim review and limits

The fixture demonstrates one least-privilege pattern: a namespaced Role and
RoleBinding grant `get` and `patch` on one named object, including to a
ServiceAccount whose Pod runs in a separate operator namespace. Kubernetes
documents that Role scope is namespaced, RoleBindings can bind a ServiceAccount
from another namespace, and `resourceNames` restricts selected operations to
named resources. This does not establish that every AI operator can function
with these exact permissions. An operator's actual RBAC must be derived from
its documented release artifacts and exercised against the resources it needs;
some controllers require cluster-scoped CRD, node, or scheduling operations.

The pinned control does not identify primary sources for its product-wide
claims that the named operators generally need cluster-wide privileges or that
namespace restrictions alone define the lateral-movement boundary. This case
does not independently verify those claims; assess each operator's actual
RBAC and deployment model from its current official manifests and docs.

The control's vulnerability-management and upgrade-cadence statement is not
verified here. There is no synthetic CVE evaluation, version scanner, due-date
policy, or vendor upgrade. Applicability is operational and vendor-specific:
for example, NVIDIA's current GPU Operator upgrade documentation describes
version-dependent CRD upgrade steps, Helm or OLM paths, component compatibility,
and special driver-upgrade considerations. A generic calendar cadence cannot
replace checking each operator's supported Kubernetes, driver, CRD, and
component matrix and its current security advisories. Apply that vendor process
only to an actually deployed product and supported platform.

This case also does not establish network isolation, image provenance or
scanning, vulnerability status, production identity lifecycle, multi-tenant
policy, or protection against a compromised operator process. No CRD is
installed and no exploit or vulnerability is reproduced.

## Sources

- [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes ServiceAccounts](https://kubernetes.io/docs/concepts/security/service-accounts/)
- [Kind releases](https://github.com/kubernetes-sigs/kind/releases) — v1.36.1 node image digest
- [Python Official Image](https://hub.docker.com/_/python) — pinned probe image digest
- [NVIDIA GPU Operator upgrade guide](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/latest/upgrade.html) — vendor-specific procedure example
