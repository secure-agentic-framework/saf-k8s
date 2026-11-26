# SAF-K8S-0910-027 scheduled drift reference

Run `python3 lab.py test SAF-K8S-0910-027` from the control lab.

## Portable evidence scope

The original case proves a native ValidatingAdmissionPolicy/Binding on two owned Kubernetes v1.36.1 API servers, scoped one-field binding drift, actual Admission behavior on the healthy and drifted members, bounded host-run repair, independent readback, and cleanup. The scheduled check reintroduces the same `validationActions: Deny -> Warn` change on the owned peer after those checks. A namespace-scoped CronJob then runs as a real projected ServiceAccount workload, reads the exact binding using the in-cluster API CA, repairs it with resourceVersion concurrency protection, verifies state, and creates an immutable metadata-only ConfigMap receipt. The runner verifies the successful Job has the exact owner UID and scheduled timestamp and reads the receipt using a distinct read-only fixture identity.

One pass is scheduled at the next minute boundary, with a bounded wait of up to 105 seconds. Receipt data is limited to member UID, named binding, desired/observed revisions, observed and restored action values, detection time, and repair verification. Verify recurring coverage, alert routing, failure recovery, concurrency, exceptions and governance for each real member and adopted policy class.

## Fixture and adoption

- `drift_monitor.py` uses only the mounted in-cluster CA/token and standard library HTTPS calls. It never prints or persists credentials.
- `cronjob.yaml` bounds one CronJob to a non-root, read-only-root, unprivileged pod with no host mounts. Its ClusterRole names only the one binding; receipt creation is confined to `saf-test`.
- The helper's Python image is architecture/digest validated by the existing owned-runtime helper and preloaded into the separate peer by the existing owned-peer helper.
- The fixture suspends CronJob scheduling once it has read the successful receipt; the enclosing owned-peer context still deletes the peer cluster in `finally`.
- The internal ConfigMap receipt records the bounded repair. Verify any external alert delivery on the deployed route.

[Kubernetes v1.36 CronJob scheduling](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/#job-creation)
