# SAF-K8S-0403-011 — Secret re-encryption after key rotation

A disposable Kubernetes v1.37.0 kind cluster uses fresh temporary Secretbox keys.
Two synthetic Secrets are stored under the old key. After the API server reloads
its encryption configuration, a separate synthetic sentinel proves new writes
use the new key while the two unchanged records retain their old envelopes.

The case creates a `storagemigration.k8s.io/v1` StorageVersionMigration for the
core `secrets` resource. It requires the native controller's successful terminal
condition, observes the new encrypted envelope on both originally old records,
and verifies both inert API read values are preserved. The receipt keeps only
sanitized key labels and marker comparisons. The runner deletes the owned
cluster and temporary key files.

This establishes the rewrite mechanism and exact-record verification. Evidence
for actual KMS key rotation, scheduling, key-version audit, complete production
Secret inventory, recoverable backups, and old-key retirement is separate.

```sh
python3 lab.py test SAF-K8S-0403-011 --docker-context desktop-linux
```

In the framework repository use `python3 tests/control-lab/lab.py` with the same
arguments. Use a kubectl client within the supported skew for v1.37.

- [Kubernetes v1.37 Storage Version Migration](https://kubernetes.io/blog/2026/08/31/kubernetes-v1-37-storage-version-migration-ga/)
- [Kubernetes Storage Version Migration procedure](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/storage-version-migration/)
- [Kubernetes encryption at rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
