# SAF-K8S-0701-002 — CSI driver permissions and storage authorization

```sh
python3 lab.py test SAF-K8S-0701-002 --docker-context desktop-linux
```

The nonroot fixture Pod in a disposable Kubernetes v1.36.1 cluster uses
its projected ServiceAccount token and TLS CA to authenticate to its own
API server. The authentication review identifies that exact synthetic
ServiceAccount. Its seven authorization queries initially return denial.
A namespaced fixture RoleBinding permits two named read queries, while the
same identity still has no permission to create StorageClasses, list
snapshot classes or contents, or create or delete VolumeSnapshots.

The test queries the API server's authorization decision for its own identity.
Actual driver deployment approval and privileges, snapshot APIs/controllers,
backend behavior, provider equivalence, and release compatibility require
their own evidence.

- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes v1.36 Volume Snapshots](https://v1-36.docs.kubernetes.io/docs/concepts/storage/volume-snapshots/)
- [Kubernetes external snapshotter release compatibility](https://github.com/kubernetes-csi/external-snapshotter/releases/tag/v8.6.0)
