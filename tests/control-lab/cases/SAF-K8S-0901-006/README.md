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

## Kueue and Volcano source review

The control statement groups Kueue and Volcano, but their queue models are
different and neither is installed in this minimal case.

- Kueue v0.20.7 documents support for Kubernetes 1.34 and newer, including
  this cluster version. It is still a cluster-scoped controller installation
  with CRDs and a webhook, beyond the single-cluster native quota/RBAC slice.
  This starter case avoids adding a second controller lifecycle and image
  supply chain before the quota and tenant boundary have their own reviewable
  evidence. Consequently Kueue runtime coverage is explicitly pending; the
  case makes no claim that native ResourceQuota is a substitute for Kueue.
- Kueue documents `ClusterQueue` as a cluster-scoped resource pool that
  establishes quota and fair-sharing policy. A namespaced `LocalQueue` points
  to one `ClusterQueue`; users submit supported Jobs through that queue, and
  Kueue reserves quota as part of workload admission. Workload priority affects
  admission order, and preemption behavior depends on the configured policy.
  Thus a `LocalQueue` alone is not an independent tenant quota, and Kueue does
  not imply priority restrictions or preemption safeguards without reviewed
  configuration and RBAC. Kueue's documented default is all-or-nothing
  admission unless Partial Admission is explicitly enabled. This case does not
  exercise those APIs, Job integrations, admission gates, fair sharing,
  borrowing, or preemption.
- Volcano documents `Queue` as a collection of PodGroups and a basis for
  resource division. Its `capability`, `deserved`, and `guarantee` fields have
  different meanings; `deserved` depends on the capacity plugin. Gang
  scheduling and queue behavior also depend on Volcano controller/scheduler
  configuration and enabled actions/plugins. A Volcano Queue is not equivalent
  to a Kueue ClusterQueue or a Kubernetes ResourceQuota. This case installs no
  Volcano CRDs or controller and tests none of those runtime semantics.

## Coverage and unresolved claims

**Observed by this case after supervisor execution:** one namespace quota's
effect on API admission for CPU and memory requests; one allowed low-resource
mock Pod; denial of tenant ResourceQuota creation; and a scoped positive
platform authorization check. The committed source is a test design until the
supervisor executes and reviews the raw evidence from both runs.

**Not covered / pending:** Kueue and Volcano installation/version compatibility
and runtime behavior; GPU or other extended-resource quotas; distributed
training Jobs or all-or-nothing gang scheduling; queue depth or fair-share
policy; priority-class assignment/admission; scheduler preemption, reclamation,
starvation, or deadlock behavior; controller and CRD RBAC; cross-namespace
isolation; quota update/delete protection; workload limits/defaults; real
identity-provider mapping; and managed-cluster behavior. No starvation or
abuse scenario is simulated.

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
