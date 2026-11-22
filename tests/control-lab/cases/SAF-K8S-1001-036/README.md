# SAF-K8S-1001-036 — Effective audit retention configuration

```sh
python3 lab.py test SAF-K8S-1001-036 --docker-context desktop-linux
```

From the SAF-K8S checkout, run `python3 tests/control-lab/lab.py` with the same arguments. The Kubernetes v1.36.1 Kind fixture captures a native API audit record and stores its exact bytes on a pinned Versity S3 gateway using a local-path PVC.

Separate checker Jobs read the live Object Lock configuration and report the missing default or a measured one-day default below the fixture's two-day minimum. The gateway applies the one-day default to the earlier audit version. After the default changes to three days, a new copy inherits the corrected period. The same checker flags the earlier version despite the bucket's corrected default. The fixture verifies each uploaded version ID, retrieved digest, and retention interval using the backend's LastModified and RetainUntilDate fields.

The two-day minimum is a synthetic test input. Production retention schedules, exception handling, continuous monitoring and coverage across actual audit backends require separate evidence.

[Kubernetes audit logging](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/) · [GetObjectLockConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectLockConfiguration.html) · [Versity default retention behavior](https://github.com/versity/versitygw/discussions/2521)
