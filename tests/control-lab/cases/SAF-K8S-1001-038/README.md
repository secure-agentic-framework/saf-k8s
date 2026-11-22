# SAF-K8S-1001-038 — Centralized retention for audit, training, and inference logs

```sh
python3 lab.py test SAF-K8S-1001-038 --docker-context desktop-linux
```

From the SAF-K8S checkout, run `python3 tests/control-lab/lab.py` with the same arguments. A fresh Kubernetes v1.36.1 Kind cluster supplies an actual kube-apiserver audit event and two workload log streams. A local, digest-pinned Versity S3 gateway archives the source records under distinct class paths.

The fixture policy specifies three days for audit logs, five for training logs and seven for inference logs. The checker reads effective retention for each exact S3 version. It detects the initial two-day audit setting while both other classes match the policy. The corrected route applies three days to a new audit record. The case also extends the original audit version to the approved period and retrieves the original bytes for all stored records.

The durations are fixture inputs. Production log-class coverage, GPU and platform telemetry, approved schedules, lifecycle expiration, and recovery across production retention windows require separate evidence.

[Kubernetes audit events](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/) · [Versity gateway v1.9.0](https://github.com/versity/versitygw/releases/tag/v1.9.0) · [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
