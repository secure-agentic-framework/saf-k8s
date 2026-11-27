# SAF-K8S-0703-007 — Kueue sharing, reclamation and grouped admission

From the framework checkout, run the disposable queue comparison.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0703-007 --docker-context desktop-linux
```

From the lab checkout, invoke `python3 lab.py` with the same arguments.
The pinned Kueue v0.20.6 controller demonstrates one tenant's borrowed
unit, the other tenant waiting, and reclaiming that exact borrowed unit
while retaining both nominal reservations. A separate two-Pod Job
requests two units of an unallocated synthetic resource. With a quota of
one, the exact Job is suspended and has no Pods. With quota restored to
two, the same Workload is admitted and two Pods are created. Both Pods
remain unassigned because the fixture has no device allocation.

## Verify the adopted scheduler and accelerator policy

1. Inventory actual job controllers, queues, cohorts, weights, installed
   versions, node and device inventory, and the supported group placement
   or running-readiness mechanism. Verify which owners may submit to and
   change each queue and allocation.
2. In a bounded approved test pool, compare steady state, borrowing from
   one tenant, and reclamation when another eligible tenant requires its
   nominal quota. Observe workload admission, preemption, timing and
   effective allocations against documented sharing and fairness rules.
3. For each workload requiring coordinated placement, compare capacity
   below and at the complete group requirement. Observe admission,
   physical device assignment, workload-wide readiness and bounded
   recovery after an expected startup or device fault. Record the
   scheduler, actual IDs, and meaningful Ready or completion outcomes.
4. Retain effective policy and quota, approved comparison conditions,
   workload and service observations, and alert or exception handling.

[Kueue fair sharing and preemption](https://kueue.sigs.k8s.io/v0.20/docs/concepts/preemption/)
and [Kueue all-or-nothing scheduling](https://kueue.sigs.k8s.io/v0.20/docs/concepts/all_or_nothing/).

## Bounded CPU group readiness

A separate case-owned ClusterQueue and LocalQueue admit one two-Pod CPU Job.
The harness verifies the exact queue admission, observes `PodsReady=True` and
both Job-owned Pods Ready, then verifies completion and the matching
Workload's `Finished=True`. This comparison adds two checks. Each Pod requests
10m CPU and 16 MiB and runs an idle bounded process. Actual device assignment,
coordinated placement, failure recovery and long-run fairness remain adopter
verification. See [Kueue v0.20 Workload API](https://kueue.sigs.k8s.io/v0.20/docs/reference/kueue.v1beta2/).

## Cohort quota reclamation and recovery

This phase uses two Kueue ClusterQueues in one cohort. Each Job requests 100m CPU and
32Mi memory. Team A's first Job uses its nominal CPU quota and keeps the same Ready Pod
through reclamation. Its second Job borrows 100m CPU and reaches Ready while team B's Job
waits. The fixture checks that memory usage stays within nominal quota.

Enabling team B's `reclaimWithinCohort: Any` setting makes the pinned controller record
`Evicted=Preempted` and `Preempted=InCohortReclamation` for the borrowing Workload. The
condition includes the exact preemptor Workload and Job UIDs. The peer becomes Ready.
The fixture removes that Job using a UID precondition and independently verifies the
preemptor Workload UID is gone. The original victim Job and Workload return to admission
with a new Ready Pod UID.

The recovery phase covers CPU-backed nominal quota reclamation. Weighted-share
preemption, sustained fairness, actual accelerator placement and gang recovery require
separate evidence. See [Kueue v0.20 preemption](https://kueue.sigs.k8s.io/v0.20/docs/concepts/preemption/)
and the [pinned Workload API](https://kueue.sigs.k8s.io/v0.20/docs/reference/kueue.v1beta2/).

## Additive weighted fair-sharing preemption discriminator

The weighted-share phase uses a distinct flat cohort with three ClusterQueues
and one shared ResourceFlavor. Team A has 100m nominal CPU and runs a 100m
baseline plus a 100m lower-priority victim, so its live reservation borrows
100m. Team B has 100m nominal CPU, the idle donor queue has 300m, and the
preemptor requests 400m CPU plus 32Mi memory. Each queue has a memory nominal
quota (128Mi for A/B, 256Mi for donor), so the case exercises CPU borrowing
only. The donor provides enough unused quota after the exact victim is removed;
without removing that victim, the 400m preemptor is 100m beyond available
cohort CPU quota.

The preemptor has explicit Kueue WorkloadPriorityClass value 50; the victim
uses default value 0 and the protected baseline value 100. With quota, priority,
request, and policy inputs fixed, the case first observes the peer pending at
fair-sharing weight 1 and the victim and baseline still Ready. It then changes
only the peer ClusterQueue's `spec.fairSharing.weight` to 10. The expected
witness is the exact victim's `Evicted=Preempted` and
`Preempted=InCohortFairSharing` conditions, the exact preemptor Job and Workload
UIDs in the message, the unchanged baseline Pod, and 300m CPU borrowing by the
admitted preemptor. Raw evidence retains both queue weighted-share observations
and both complete quota snapshots. After UID-precondition deletion of the
preemptor, the case verifies recovery of the same victim Job and Workload with a
new Ready Pod. The cohort is implicit from its name; the case creates no
explicit Cohort object.

This comparison exercises the pinned controller's fair-sharing preemption path.
Long-run scheduling fairness and accelerator placement require separate evidence. Kueue documents the supported
share strategies and the effect of `spec.fairSharing.weight` in its
[v0.20 preemption guide](https://kueue.sigs.k8s.io/v0.20/docs/concepts/preemption/)
and [v0.20 Fair Sharing guide](https://kueue.sigs.k8s.io/v0.20/docs/concepts/fair_sharing/).
