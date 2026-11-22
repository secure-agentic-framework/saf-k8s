# SAF-K8S-1001-026 durable audit delivery

Run from the SAF-K8S framework checkout with OpenSSL and the usual Kind prerequisites.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1001-026 --docker-context desktop-linux
```

The Kubernetes v1.36.1 API server delivers native audit webhook batches over
TLS to a fixture receiver. The audit policy selects metadata for ConfigMap
requests in the fixture namespace. The runner matches the API response's
Audit-Id to the actual delivered ResponseComplete event.

Recreating an emptyDir-backed receiver loses the first event. Recreating the
PVC-backed receiver keeps the prior event and uses the same claim and volume
binding. A new, distinct audit event reaches the replacement receiver.
The receiver writes each batch to disk and calls fsync before acknowledging it.

The case creates a temporary CA and named TLS certificate for each run. The
cluster has a case-owned local-path PVC. Production exporters, managed control
planes, protection of audit storage, retention policy, and storage across a
node or other failure domain require separate evidence.

- [Kubernetes v1.36 audit backends](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Kubernetes v1.36 persistent volumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/persistent-volumes/)
