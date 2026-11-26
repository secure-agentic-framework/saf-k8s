# SAF-K8S-0901-006 — Native namespace quota and tenant authorization

Run from the control lab root with the configured local Docker context:

```sh
python3 lab.py test SAF-K8S-0901-006 --docker-context desktop-linux
```

The lab runner creates a fresh disposable Kind Kubernetes v1.36.1 cluster with
its digest-pinned node image. The disposable fixtures use digest-pinned Python,
workload and Kueue controller images. The runner verifies the upstream Kueue
manifest digest before installing the controller. All request data belongs to
the fixture.

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
provides quota and governs scheduling policy. The quota and priority checks use
one synthetic tenant and LocalQueue. The fair-sharing check uses three
case-owned LocalQueues with finite CPU-only Jobs. Volcano uses its own Queue and
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

## Bounded Kueue fair-sharing and FIFO observations

This scratch extension preserves the published case's 21 checks and adds a
separate CPU-only comparison on pinned Kueue v0.17.7. The AFS fixture compares
equal-priority, equal-input pending Workloads after releasing a 100m holder and
observes the newer lower-use Workload first. An independent ClusterQueue sets
`admissionMode: NoAdmissionFairSharing` with `StrictFIFO`. It observes the exact
100m seed's Workload assignment, Ready Job-owned Pod, completion, and absence
from the peer queue; before release it rechecks equal live priorities and
seed-matched candidate inputs. It then observes the older candidate admitted
first and the younger candidate admitted after the older reservation is
released. Exact API objects, queue accounting, quantities and timestamps are
retained in raw evidence; normalized booleans feed the receipt. This is a
bounded single-selection CPU observation, not evidence for GPU resources,
production demand behavior, preemption, Volcano, or managed clusters.

The existing indexed readiness-timeout fixture also records its exact Job and
Workload UIDs and raw `status.requeueState` before foreground deletion. It waits
for those exact UIDs and Job-owned Pods to disappear before the separate FIFO
queue phase. This scopes fixture cleanup to the pinned controller's global
PodsReady gate, whose v0.17.7 implementation considers Workloads across
ClusterQueues.

The version-pinned implementation is in the [v0.17.7 scheduler gate](https://github.com/kubernetes-sigs/kueue/blob/v0.17.7/pkg/scheduler/scheduler.go), [scheduler cache readiness check](https://github.com/kubernetes-sigs/kueue/blob/v0.17.7/pkg/cache/scheduler/cache.go), and [ClusterQueue readiness tracking](https://github.com/kubernetes-sigs/kueue/blob/v0.17.7/pkg/cache/scheduler/clusterqueue.go).

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


## Kueue historical-use admission

The pinned Kueue controller samples a separate, case-owned CPU LocalQueue.
One 100m seed Job creates observable usage history. The two competing Jobs
have equal live Workload priorities and the same resource requests. A third
Job holds quota until the seeded queue and unseeded queue are both waiting.
The case checks their live history immediately before release, observes
admission of the newer lower-use Workload, then observes admission of the
older peer after the first reservation is released. Exact Workload and Job
identities and queue accounting are retained in the raw evidence.

This exercises the enabled mode for one controlled CPU workload profile. The
mode-off FIFO comparator, Volcano, GPU and adopted fairness remain separate
verification work.

[Kueue Admission Fair Sharing](https://kueue.sigs.k8s.io/v0.17/docs/concepts/admission_fair_sharing/)

The controller rollout has a 180-second startup bound. The measured workload readiness timeout and queue assertions keep their original bounds.

The pending-state probe checks the exact Job owner, suspension and the absence
of admission or reservation. StrictFIFO can leave a later Job unevaluated while
the head of the queue is waiting, so the probe also accepts an unset quota
condition. It independently checks 100m held by the exact holder and zero
reserved by either contender before release.


## Bounded within-queue preemption and recovery

The additive scratch extension creates a separate CPU-only Kueue v0.17.7
ClusterQueue with `withinClusterQueue: LowerPriority`, no cohort, and 100m
nominal CPU quota. It observes an admitted 100m victim with its exact
Job-owned Ready Pod, then creates a same-queue 100m preemptor whose live
WorkloadPriorityClass value is higher. The witness checks `Evicted=True` with
reason `Preempted`, victim Job suspension and owned-Pod removal, plus the
preemptor's admission and Ready Pod. Before checking recovery, it records the
preemptor's exact Job and Workload UIDs and status, foreground-deletes that Job,
and waits for those exact UIDs and its owned Pod to disappear. It then verifies
the same victim Job UID receives quota and a distinct replacement Ready Pod.
Raw API objects are persisted by phase; receipt observations use stable
booleans.

This demonstrates one explicitly configured same-ClusterQueue
lower-priority preemption and recovery path. It does not establish cohort or
cross-queue preemption, other controller policies, Volcano, accelerator
behavior, production demand behavior, or adopted-cluster configuration. The
pinned policy and candidate logic are in the [Kueue v0.17.7 preemptor](https://github.com/kubernetes-sigs/kueue/blob/v0.17.7/pkg/scheduler/preemption/preemption.go)
and [priority policy](https://github.com/kubernetes-sigs/kueue/blob/v0.17.7/pkg/scheduler/preemption/common/preemption_policy.go).
