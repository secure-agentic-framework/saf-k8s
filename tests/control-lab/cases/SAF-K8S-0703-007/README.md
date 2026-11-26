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
