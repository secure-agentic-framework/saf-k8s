# SAF-K8S-1001-024 — Append-only audit storage

```sh
python3 lab.py test SAF-K8S-1001-024 --docker-context desktop-linux
```

From the SAF-K8S checkout, run `python3 tests/control-lab/lab.py` with the same arguments. The case starts a fresh Kubernetes v1.36.1 Kind cluster and captures the exact native audit records for three synthetic ConfigMap creates. A dedicated in-cluster ServiceAccount appends the original bytes as individually named immutable ConfigMaps.

The API denies append before the RoleBinding. After binding, the writer can append and read named records. Admission denies a mutable append. RBAC denies the writer's update and delete requests, and a second create with the first name and different content conflicts. A separate maintenance role can patch an explicitly mutable comparator and receives the native immutable-field denial on the archived record. The final list preserves the sequence, original UIDs and byte digests.

The fixtures cover Kubernetes API storage and ordinary scoped identities in the disposable cluster. Production log ingestion completeness, storage administration and exception boundaries, and centralized SIEM or archive durability require separate evidence.

[Kubernetes immutable ConfigMaps](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/configmap/#immutable-configmaps) · [Kubernetes audit records](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/) · [RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/) · [Validating admission policies](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
