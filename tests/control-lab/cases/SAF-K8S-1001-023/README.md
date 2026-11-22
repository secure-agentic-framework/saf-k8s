# SAF-K8S-1001-023 — Scheduled retrieval of native Kubernetes audit records

```sh
python3 lab.py test SAF-K8S-1001-023 --docker-context desktop-linux
```

From the SAF-K8S checkout, run `python3 tests/control-lab/lab.py` with the same arguments. The fresh v1.36.1 Kind cluster writes a scoped Metadata audit log. The case correlates three real API response Audit-Ids with the exact native audit lines and archives the original bytes in two gzip JSONL bundles. A separately mounted, immutable index records the lookup target and compressed SHA-256.

An unchecked reader follows a readable wrong target and returns the wrong historical event. The checked reader identifies that digest mismatch and reports a missing archive object separately. A healthy comparator retrieves a different expected record. Two Kubernetes CronJob executions each use a new Pod to retrieve the same previously archived record and digest. The evidence retains both Job schedule timestamps, Job and Pod UIDs, the actual index, and the compressed archive bytes.

The fixtures use immutable ConfigMaps for the archive and index within one disposable cluster. Production storage redundancy, format migration and retrieval coverage over the actual retention window require deployment evidence.

[Kubernetes audit events](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/) · [CronJob scheduling and timestamps](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/) · [Immutable ConfigMaps](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/configmap/#immutable-configmaps)
