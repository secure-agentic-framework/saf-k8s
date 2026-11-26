# SAF-K8S-0901-006 — Native namespace quota and tenant authorization

Run from the control lab root with the configured local Docker context:

```sh
python3 lab.py test SAF-K8S-0901-006 --docker-context desktop-linux
```

The lab runner creates a fresh disposable Kind Kubernetes v1.36.1 cluster with
its digest-pinned node image. This case also pins its Python probe and mock
workload image by digest. It does not contact an external registry manifest,
install an operator, or use real tenant data.

## Case behavior

The tenant ServiceAccount gets only `create` on Pods in one synthetic namespace.
The case starts a projected-token probe Pod, then submits a mock Pod requesting
600m CPU and 128Mi memory while no ResourceQuota exists. The API creates it and
the case waits for it to become Ready (**red**). The temporary Pod is deleted.

The case applies a namespace ResourceQuota of four Pods, 500m aggregate CPU
requests, and 256Mi aggregate memory requests. The same 600m mock request must
then receive HTTP 403 with a quota-specific message (**green**). A 100m / 64Mi
mock Pod must still be created and become Ready (**green**). The tenant's
projected identity must be denied a dry-run ResourceQuota create, while a
separate platform ServiceAccount with a namespace Role granting only
`resourcequotas.create` must receive a successful dry-run create response
(**positive**). Probe output contains response status and sanitized API
diagnostics; it never prints bearer tokens or Secret data.

The fixture demonstrates Kubernetes namespace quota accounting and a small
namespaced RBAC boundary. Kubernetes ResourceQuota constrains aggregate
namespace consumption; it does not model proportional cluster sharing or
prevent contention between namespaces. A ResourceQuota must exist for the
namespace, and its update/delete governance is a separate control obligation.
This test only verifies that the tenant cannot create a ResourceQuota and that
the bounded platform identity can create one in server-side dry-run. It does
not prove that all other cluster principals are restricted or that production
quota objects cannot be changed or removed.

## Kueue and Volcano scope

The fixture installs pinned Kueue v0.17.7 and exercises its Job integration.
The namespaced `LocalQueue` selects a cluster-scoped `ClusterQueue`, which
provides quota and governs scheduling policy. The fixture selects one tenant,
one LocalQueue, and finite CPU-only Jobs. Volcano uses its own Queue and
PodGroup model. Verify the scheduler actions and plugins for any adopted
Volcano deployment, including capacity, deserved, and guarantee semantics.

For adoption, verify actual GPU or other extended-resource allocation,
queue administration, approved workload priorities, ordering and fair sharing
under representative demand, preemption configuration, protected recovery,
and managed-cluster behavior.

## Primary sources

- [Kubernetes v1.36 ResourceQuota](https://v1-36.docs.kubernetes.io/docs/concepts/policy/resource-quotas/)
- [Kubernetes v1.36 RBAC authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kueue v0.20.7 installation and supported Kubernetes versions](https://kueue.sigs.k8s.io/docs/getting-started/installation/)
- [Kueue ClusterQueue](https://kueue.sigs.k8s.io/docs/concepts/cluster_queue/)
- [Kueue LocalQueue](https://kueue.sigs.k8s.io/docs/concepts/local_queue/)
- [Kueue workload admission](https://kueue.sigs.k8s.io/v0.20/docs/concepts/admission/)
- [Kueue all-or-nothing scheduling](https://kueue.sigs.k8s.io/docs/concepts/all_or_nothing/)
- [Volcano v1.15 Queue resource management](https://volcano.sh/docs/v1.15.0/keyfeatures/queueresourcemanagement/)
- [Volcano Queue](https://volcano.sh/docs/concepts/queue/)
- [Volcano scheduler actions](https://volcano.sh/docs/scheduler/actions/)

## Kueue queue admission

The same case installs upstream Kueue v0.17.7 in the isolated cluster. It
verifies the official manifest bytes before replacing the image tag with the
pinned controller digest. The tenant LocalQueue uses a restricted ClusterQueue
with 300m CPU of nominal quota. A two-Pod batch requesting 400m CPU stays held
without child Pods. A two-Pod batch requesting 200m receives quota and both
workers emit the exact fixture receipt. An authorization check bounds queue
administration to the selected namespace. This section requires access to the
public Kueue release artifact and the pinned container images.

- [Kueue v0.17 installation](https://kueue.sigs.k8s.io/v0.17/docs/installation/)
- [Kueue v0.17 Jobs](https://kueue.sigs.k8s.io/v0.17/docs/tasks/run/jobs/)

The controller also uses a 15-second all-Pod readiness timeout. A healthy batch
reaches the Kueue PodsReady condition. In an indexed two-worker comparator,
both Pods run and exactly one reaches Ready. The Workload then reports
PodsReadyTimeout, the Job is suspended, its Pods are removed, and its quota is
released. These observations cover Kueue's timeout-based mechanism in the lab.

- [Kueue v0.17 all-Pod readiness](https://kueue.sigs.k8s.io/v0.17/docs/tasks/manage/setup_wait_for_pods_ready/)

## Named workload priority

The case creates two low-risk fixture `WorkloadPriorityClass` objects.
Before activation, a fixed tenant identity can server-dry-run proposals for the
elevated class, a missing Kueue class, and a separate Pod `PriorityClass`.
After activation, the same requests and a proposed elevated update are
refused. The approved tenant Job is created with `tenant-normal` (10).
Independent Kueue Workload reads verify `spec.priorityClassRef` group, kind,
and name, the numeric `spec.priority`, and the exact LocalQueue. Both
approved low-CPU workers complete. The scope is this named tenant policy,
bounded quota and readiness handling. [Kueue v0.17 API reference](https://kueue.sigs.k8s.io/v0.17/docs/reference/kueue.v1beta2/).
