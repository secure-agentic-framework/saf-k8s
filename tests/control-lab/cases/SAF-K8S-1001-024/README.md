# SAF-K8S-1001-024 — Append-only audit storage

```sh
python3 lab.py test SAF-K8S-1001-024 --docker-context desktop-linux
```

From the SAF-K8S checkout, run `python3 tests/control-lab/lab.py` with the same arguments. The case starts a fresh Kubernetes v1.36.1 Kind cluster and captures the exact native audit records for three synthetic ConfigMap creates. A dedicated in-cluster ServiceAccount appends the original bytes as individually named immutable ConfigMaps.

The API denies append before the RoleBinding. After binding, the writer can append and read named records. Admission denies a mutable append. RBAC denies the writer's update and delete requests, and a second create with the first name and different content conflicts. A separate maintenance role can patch an explicitly mutable comparator and receives the native immutable-field denial on the archived record. The final list preserves the sequence, original UIDs and byte digests.

The fixtures cover Kubernetes API storage and ordinary scoped identities in the disposable cluster. Production log ingestion completeness, storage administration and exception boundaries, and centralized SIEM or archive durability require separate evidence.

[Kubernetes immutable ConfigMaps](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/configmap/#immutable-configmaps) · [Kubernetes audit records](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/) · [RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/) · [Validating admission policies](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)

## Adopter verification

1. Inventory audit ingestion destinations, record writer/reader/maintenance principals, and each storage administrator or exception route.
2. In a controlled rehearsal with synthetic records, confirm the normal writer can append and read only its intended records but cannot update, delete, or overwrite an existing record. Verify mutable comparator records remain separate from archived records.
3. Verify approved maintenance operations require the documented authority and leave an independent audit trail. Check effective object-lock/immutability settings or equivalent at primary and replicated stores.
4. Retain effective role/policy settings, denied and permitted operation results, immutable record identifiers/digests, and independent review evidence.
