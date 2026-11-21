# SAF-K8S-0102-008 — Trusted etcd snapshot verification and restore

```sh
python3 lab.py test SAF-K8S-0102-008
```

The case opens one synthetic Kubernetes v1.36.1 kind cluster and takes an
etcd snapshot containing a public ConfigMap marker. It records the expected
SHA-256 digest separately from staging and checks the native snapshot
metadata. A truncated copy and a second, valid snapshot taken after a marker
change both fail the trusted digest check. Neither enters the restore path.

The intact staged artifact is verified again and restored with native hash
checking, a revision bump, and compaction. The recovery container uses
Docker network mode `none`. The test reads only the exact synthetic
ConfigMap record and confirms that the old revision is compacted. Artifact
contents and keys stay out of test evidence.

The detached reference and recovery artifacts live in a private temporary
directory. Production provenance depends on protection of the expected
digest or validation of a trusted signature. Backup custody, managed export
compatibility, and Kubernetes controller recovery remain separate deployment
checks.

- [etcd v3.6 disaster recovery](https://etcd.io/docs/v3.6/op-guide/recovery/)
- [Kubernetes v1.36 operating etcd](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/configure-upgrade-etcd/)
