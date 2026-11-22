# SAF-K8S-0703-005 — AI workload resource exhaustion guardrails

```sh
python3 lab.py test SAF-K8S-0703-005 --docker-context desktop-linux
python3 -B cases/SAF-K8S-0703-005/test_static.py
```

The Kubernetes v1.36.1 lab observes permissive baseline dry-runs and
then separately verifies the resource policies below.

- The LimitRange supplies a 16 MiB container memory request and a 32 MiB
  default limit, rejects a declaration above 64 MiB, and permits a
  declaration at the ceiling.
- The same LimitRange caps requested storage at 8 MiB per PVC. Two 8 MiB
  claims are persisted and accounted for in a 16 MiB namespace quota. A
  third 1 MiB request is refused by the storage quota.
- A bounded, nonroot fixture Job runs a synthetic two-item queue and
  16-byte input limit. It rejects an oversized input without consuming
  queue capacity, returns a retry delay at saturation, and accepts the
  retry after FIFO completion frees a slot.
- The Job controller observes an inert sleeper's declared resources and
  returns `DeadlineExceeded` after its configured 20-second deadline.
  The lab requires a Ready Job-owned Pod before observing expiry.

These are container admission bounds, requested storage, a synthetic
queue model, and one Job lifecycle. Aggregate runtime memory, training
dataset sizing and ingestion, actual queue controllers, throughput,
failures and production recovery require separate evidence.

- [Kubernetes v1.36 LimitRange](https://v1-36.docs.kubernetes.io/docs/concepts/policy/limit-range/)
- [Kubernetes v1.36 ResourceQuota](https://v1-36.docs.kubernetes.io/docs/concepts/policy/resource-quotas/)
- [Kubernetes v1.36 Jobs](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/job/)
