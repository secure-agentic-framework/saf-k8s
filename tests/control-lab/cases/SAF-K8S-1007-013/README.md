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

## Typed sources and inventory reconciliation

The same read-only identity also lists native Service, PVC and Job objects and
records each UID and per-kind list resource version. The separate fixture
writer persists the initial inventory after API admission denies creation by the
reader identity. With the watch disconnected, the fixture replaces the Job
and changes the Service port. A fresh list repairs the durable inventory,
preserving the unchanged PVC and Service identities and removing the former Job.

## Verify your implementation

1. List the authoritative sources, collection scopes and owner for each asset
   class. Enumerate relevant clusters and namespaces. Link model IDs and
   artifact digests to deployed workload releases, datasets to PVCs and
   approved storage inventory, pipelines to their run records, and inference
   endpoints to Services, EndpointSlices or the applicable gateway APIs.
   Verify an actual device allocation from the authorized kubelet or driver
   producer. A workload's GPU request describes intent.
2. Verify the collector's effective list/watch permissions and its isolation
   from the publisher. Keep Kubernetes object UID and scope alongside each
   external source's identity and version. Validate representative matches
   against source records and check duplicate names across namespaces or
   replacement objects. Retain the collection time and per-source cursor.
3. Observe representative additions, meaningful changes and deletions from
   each source. Verify that an interrupted or expired watch triggers a fresh
   list or equivalent source reconciliation. Remove obsolete entities and
   repair references before updating publication status. Resource versions
   are opaque; record them with their own API source.
4. Agree freshness limits and permitted gaps per source. Collect durable
   status for last successful observation, missed sources, stale publication
   and ownership exceptions, and evaluate production behavior against those
   limits. Compare a fresh source snapshot with published inventory and retain
   the differences and any retry or alert evidence.

The test covers API metadata, namespace access, watch events and a typed
relist after disconnected changes. Its PVC supplies a storage reference.
Registry objects, storage contents, and hardware allocation require evidence
from their actual owners and producers.

## Primary references

- [Kubernetes v1.36 API concepts](https://v1-36.docs.kubernetes.io/docs/reference/using-api/api-concepts/) describes LIST responses, resource versions, and watch semantics.
- [Kubernetes RBAC reference](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) documents namespace-scoped Roles, RoleBindings, and `list`/`watch` permissions.
- [Kind Quick Start](https://kind.sigs.k8s.io/docs/user/quick-start/) documents selecting a Kubernetes node image; the lab runner pins its v1.36.1 node image by digest.
