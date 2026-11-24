# SAF-K8S-1007-013 — Synthetic Kubernetes AI asset inventory

Run through the existing control-lab runner from the SAF-K8S framework checkout:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1007-013 --docker-context desktop-linux
```

The runner creates a disposable Kind v1.36.1 cluster with a digest-pinned node image. This case creates two synthetic namespaces, a read-only ServiceAccount Role and RoleBinding scoped to the owned namespace, five ConfigMap metadata fixtures, one unrelated ConfigMap there, and one unrelated ConfigMap in a separate namespace. The fixtures are Kubernetes metadata objects.

The case uses `kubectl` impersonation to submit requests as the service-account identity; Kubernetes RBAC authorizes those requests against the case-owned RoleBinding. The actual API LIST selects the synthetic ownership label. It confirms that all five declared asset-kind labels appear, while an unlabeled record does not. These are five synthetic ConfigMap metadata labels, not observations of five real AI asset classes. It then performs an actual LIST in the separate namespace and expects Kubernetes RBAC to deny it. A persistent API watch using the same identity continues from the LIST resource version, so the client can observe a new record even if its create request arrives before the watch connection opens. The case waits for and records ADDED, MODIFIED, and DELETED events, checks the synthetic revision update, and confirms through a final LIST that the deleted record is absent.

This case writes `inventory-list.raw.json`, `denied-neighbor.raw.json`, `inventory-watch.raw.json`, and raw typed-inventory snapshots for initial unknown, source gap, recovery, and relist reconciliation. These contain fixture metadata, resource versions, typed source cursors, deterministic capture times, watch events, and the expected authorization-denial response. No Secret objects are created or read, and the case does not serialize Kubernetes credentials or tokens. This describes case-written evidence only, not every artifact the lab runner may retain.

## Review of the pinned control

The control requires automated, continuously updated visibility over models, datasets, ML pipelines, inference endpoints, and GPU allocations, but it does not specify the ownership marker, authoritative source for each asset class, acceptable discovery delay, completeness criteria, identity boundary, or the evidence needed to prove that the inventory is current. This case operationalizes one narrow, explicit contract: synthetic metadata is owned when it carries the fixture label; a namespaced reader can list and watch those records; changes are observable; and a separate namespace is denied.

## Typed sources and inventory reconciliation

The same read-only identity also makes actual Kubernetes LIST requests for
native Service, PVC and Job objects. The expected source contract is those three
typed API collections in the case-owned namespace under the fixture ownership
selector. Each source snapshot records its source identity (cluster context,
API version, kind, namespace and selector), expected-coverage flag, capture
time, opaque LIST resource-version cursor, status (`fresh`, `stale`, or
`unknown`), and observed objects including UID and definition. A supplied fixed
reference clock makes timestamps and freshness decisions repeatable across
separate clusters; it is a fixture clock, not wall-clock latency evidence.

The reader is denied publication create access. The harness-side fixture writer
then uses one reconciliation function and one publication helper for every
state. An expected Job source omitted by fixture injection before any successful
observation is published as `unknown`. After a successful typed relist, the
fixture omits the Job source again at a reference time 120 seconds later. The
published state marks it `stale`, reports the observation gap, and retains its
last-good cursor and assets while the Service and PVC sources remain fresh. A
successful re-observation clears the gap; then the fixture replaces the Job and
changes the Service port, and another typed relist updates the same snapshot.
The case simulates source unavailability by temporarily removing Job LIST
access from its own reader Role. The real API denial flows through the same
publisher that observes recovery after scoped access is restored. Logical
capture times keep the freshness assertions repeatable.

## Verify your implementation

1. Write an adopter-owned source map for every required asset class: authoritative
   system and owner, endpoint or cluster, collection scope, stable source
   identity, cursor/version meaning, freshness limit, expected coverage, and
   permitted gaps. Include all in-scope clusters and namespaces. For off-cluster
   sources, collect evidence from the authoritative registry, object store or
   approved storage catalog, pipeline/run system, gateway, and device driver or
   kubelet producer. Record the native record ID/digest, version or cursor, and
   source capture time. Link those source records to deployed releases, dataset
   references, pipeline runs, endpoint routes, and actual device allocations;
   a Kubernetes workload request is only GPU intent.
2. Check each production collector's effective read permissions against its
   source map, and verify publisher credentials and write permissions are
   separately held. Preserve source identity, capture time, cursor, coverage,
   and status for every expected source. Validate representative links against
   records in the source systems, including duplicate names, replacements,
   deletions, and cross-scope ownership.
3. Cause or observe source additions, meaningful changes, deletions, missed
   polls, and watch interruption/expiration for each source. Verify that the
   production collector retries or relists, retains last-good evidence while
   declaring a gap, removes obsolete entities after successful reconciliation,
   and publishes recovery. Treat each cursor as opaque and meaningful only to
   its named source.
4. Set owner-approved numeric freshness limits and gap policy per source. Use
   the production clock and scheduler to retain last-success time, expected
   versus observed coverage, stale/unknown state, retry/alert evidence, and
   inventory-to-source differences. Pass only when the complete agreed source
   map is represented and every source is within its freshness and permitted-gap
   policy; specify the accountable owner and acceptance decision in the adopter's
   evidence packet.

The test covers synthetic ConfigMap metadata, namespace access, watch events,
typed Kubernetes LIST observations for Service/PVC/Job, and deterministic
fixture reconciliation of unknown, stale, and recovered source states. Its PVC
supplies a Kubernetes storage reference. It does not access a registry, inspect
storage contents, query a pipeline authority, resolve a real endpoint route, or
observe hardware allocation. Those require adopter evidence from the actual
authoritative systems and producers; synthetic data here is not a real
registry/storage/GPU integration.

## Primary references

- [Kubernetes v1.36 API concepts](https://v1-36.docs.kubernetes.io/docs/reference/using-api/api-concepts/) describes LIST responses, resource versions, and watch semantics.
- [Kubernetes RBAC reference](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) documents namespace-scoped Roles, RoleBindings, and `list`/`watch` permissions.
- [Kind Quick Start](https://kind.sigs.k8s.io/docs/user/quick-start/) documents selecting a Kubernetes node image; the lab runner pins its v1.36.1 node image by digest.
