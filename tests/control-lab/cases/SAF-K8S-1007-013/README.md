# SAF-K8S-1007-013 — Synthetic Kubernetes AI asset inventory

Run through the existing control-lab runner from the SAF-K8S framework checkout:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1007-013 --docker-context desktop-linux
```

The runner creates a disposable Kind v1.36.1 cluster with a digest-pinned node image. This case creates two synthetic namespaces, a read-only ServiceAccount Role and RoleBinding scoped to the owned namespace, five ConfigMap metadata fixtures, one unrelated ConfigMap there, and one unrelated ConfigMap in a separate namespace. The fixtures are Kubernetes metadata objects.

The case uses `kubectl` impersonation to submit requests as the service-account identity; Kubernetes RBAC authorizes those requests against the case-owned RoleBinding. The actual API LIST selects the synthetic ownership label. It confirms that all five declared asset classes appear, while an unlabeled record does not. It then performs an actual LIST in the separate namespace and expects Kubernetes RBAC to deny it. A persistent API watch using the same identity continues from the LIST resource version, so the client can observe a new record even if its create request arrives before the watch connection opens. The case waits for and records ADDED, MODIFIED, and DELETED events, checks the synthetic revision update, and confirms through a final LIST that the deleted record is absent.

The runner stores command output in its per-run evidence directory. This case also writes `inventory-list.raw.json`, `denied-neighbor.raw.json`, and `inventory-watch.raw.json`. They contain only API-visible fixture metadata, resource versions, watch events, and the expected authorization-denial response. No Secret objects are created or read; Kubernetes credentials and tokens are not copied into case evidence.

## Review of the pinned control

The control requires automated, continuously updated visibility over models, datasets, ML pipelines, inference endpoints, and GPU allocations, but it does not specify the ownership marker, authoritative source for each asset class, acceptable discovery delay, completeness criteria, identity boundary, or the evidence needed to prove that the inventory is current. This case operationalizes one narrow, explicit contract: synthetic metadata is owned when it carries the fixture label; a namespaced reader can list and watch those records; changes are observable; and a separate namespace is denied.

## Coverage and limits

Demonstrated by the fixture: RBAC-authorized LIST of ConfigMap metadata, filtering by a synthetic ownership label, a persistent Kubernetes WATCH using the same identity, create/update/delete observation with resource versions and revisions, final-state convergence after deletion, successful exclusion of an unlabeled record, and denial of LIST access in an unrelated namespace. Green, red, and positive assertions are independently recorded by the lab runner and can be checked against the raw API evidence.

The labels and ConfigMaps stand in for metadata only; they do not establish that real models, datasets, pipelines, endpoints, or GPU allocations can be discovered from workload resources, registries, storage systems, or device plugins. The case does not prove production completeness, freshness bounds, ownership accuracy, durable inventory storage, missed-event recovery, cross-cluster coverage, alerting, or governance workflow. It also does not inspect PVC/object-storage contents, custom resources, actual GPU state, inference behavior, model provenance, or any real feed or target. These untested interpretations and the pinned control's undefined freshness/completeness criteria remain open.

## Primary references

- [Kubernetes v1.36 API concepts](https://v1-36.docs.kubernetes.io/docs/reference/using-api/api-concepts/) describes LIST responses, resource versions, and watch semantics.
- [Kubernetes RBAC reference](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) documents namespace-scoped Roles, RoleBindings, and `list`/`watch` permissions.
- [Kind Quick Start](https://kind.sigs.k8s.io/docs/user/quick-start/) documents selecting a Kubernetes node image; the lab runner pins its v1.36.1 node image by digest.
