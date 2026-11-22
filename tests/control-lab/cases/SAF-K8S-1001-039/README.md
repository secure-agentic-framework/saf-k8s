# SAF-K8S-1001-039 — Durable retrieval of centralized AI logs

```sh
python3 lab.py test SAF-K8S-1001-039 --docker-context desktop-linux
```

From the SAF-K8S checkout, use `python3 tests/control-lab/lab.py` with the same arguments. A fresh Kubernetes v1.36.1 Kind cluster supplies a real API server audit event and synthetic training and inference workload logs. A digest-pinned Versity S3 gateway archives the three streams with versioning and a three-day COMPLIANCE Object Lock default.

The test writes a newer audit version under the same key and recreates the gateway Pod on its original bound volume. Two separate CronJob runs recover and parse all three original archive versions, matching their recorded keys, version IDs, and SHA-256 digests. Additional reader Jobs detect a missing training target and an audit version with the wrong digest. The comparison streams stay readable.

The lab uses case-owned storage credentials and an isolated Kubernetes reader service account. Production reader permissions, deployed log coverage, archive redundancy, and retrieval across actual retention windows require deployment evidence.

[Kubernetes auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/) · [Kubernetes CronJobs](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/) · [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
