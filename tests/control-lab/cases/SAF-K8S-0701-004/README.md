# SAF-K8S-0701-004 — PV reclaim policy and retained data

```sh
python3 lab.py test SAF-K8S-0701-004 --docker-context desktop-linux
```

The bundled kind local-path provisioner creates two independent 1 MiB
synthetic volumes. A scoped admission policy requires the Retain
StorageClass for claims labeled as backups. The same labeled claim
declaring the Delete class is admitted before the policy and rejected
afterward. The permitted backup claim and the scratch claim both bind
and write an inert marker.

Deleting the scratch claim removes the Delete PV and its exact
provisioned directory inside kind. Deleting the backup claim leaves the
Retain PV Released and its marker readable. Removing that PV object
still leaves the marker. The lab tears down the disposable kind node
and its fixture directories.

The result covers the named provisioner and its ordinary cleanup.
Secure sanitization, recoverability of actual backups, governed labels,
production driver behavior and dual authorization need their own evidence.

- [Kubernetes v1.36 PersistentVolume reclaiming](https://v1-36.docs.kubernetes.io/docs/concepts/storage/persistent-volumes/#reclaiming)
- [Kubernetes v1.36 StorageClass reclaim policy](https://v1-36.docs.kubernetes.io/docs/concepts/storage/storage-classes/#reclaim-policy)
- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
