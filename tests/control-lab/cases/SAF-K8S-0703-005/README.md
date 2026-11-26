# SAF-K8S-0703-005 — Job, memory, storage and queue bounds

From the framework checkout, run the disposable comparison.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0703-005 --docker-context desktop-linux
```

From the lab checkout, invoke `python3 lab.py` with the same arguments.
The native LimitRange and ResourceQuota comparisons demonstrate
per-container memory defaults and ceilings, per-claim and aggregate PVC
requested storage limits, and aggregate declared Pod memory across
containers. The same 16 MiB request and 32 MiB limit pass server-dry-run
before the memory quota and are refused after activation. A smaller Pod
still passes. The original finite Job observes its configured resource
declaration and reaches DeadlineExceeded. A separate queue model
compares bounded inputs, backpressure and retry after capacity returns.

## Verify the actual guardrails and recovery

1. Record the governed workload classes, queue and namespace owners,
   supported CPU, memory and accelerator resources, resource and active
   runtime bounds, ingress byte or object caps, and availability and
   recovery objectives. Identify the enforcement component and
   authorized policy writers at each boundary.
2. Compare effective LimitRange, ResourceQuota and Job settings with
   authorized small staging requests. Check an expected declaration,
   the exact boundary, and a refused declaration. Observe actual
   runtime behavior separately where the workload requires it.
3. Test the deployed scheduler or application queue using bounded
   synthetic work. Verify pending and approved admission, actual
   saturation signaling, bounded retry, and that the same request
   enters once after a slot becomes available. Where Kueue is used,
   capture actual queue and Workload status.
4. In an approved nonproduction path, send inert data at the configured
   size boundary and just over. Independently verify accepted input
   reaches the intended stage and rejected input is neither persisted
   nor queued. Keep corpus, credentials and unrelated tenant details
   outside the evidence.
5. Compare service health and recovery time against the documented
   objective for one bounded authorized exercise. Retain policy
   fingerprints, identity, exact decisions, cleanup and corrective
   actions.

[Kubernetes resource quotas](https://v1-36.docs.kubernetes.io/docs/concepts/policy/resource-quotas/),
[Kubernetes Jobs](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/job/),
and [Kueue Jobs](https://kueue.sigs.k8s.io/v0.20/docs/tasks/run/jobs/).
