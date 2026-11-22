# SAF-K8S-1007-018 — Deprecated API inventory and migration tracking

Run from the control-lab checkout with:

```sh
python3 lab.py test SAF-K8S-1007-018 --docker-context desktop-linux
```

The runner creates a disposable Kind v1.36.1 cluster using the digest-pinned
`kindest/node` image in `case.py`. The fixtures are owned synthetic Deployment
manifests: `extensions/v1beta1` and its documented `apps/v1` replacement. Their
mock container image uses the reserved `.invalid` domain, has zero replicas, and
is never started. There are no feeds, real workloads, targets, teams, or
notification services.

## Observable outcomes

- **Red:** live API discovery omits `extensions/v1beta1`; kubectl rejects the
  owned legacy manifest during discovery before sending an apply request. A finding with no owner or
  incomplete migration state fails the case's fail-closed upgrade gate. A
  completed record with an incorrect destination API also remains blocked.
- **Green:** an immutable, case-owned ConfigMap persists the mock notification,
  the synthetic primary/supporting role URNs, exact API mapping, completion
  state, and a reserved synthetic change reference. Readback checks the object
  UID, labels, owner, and completion data.
- **Positive:** the exact `Deployment` mapping to discovered `apps/v1` passes
  `kubectl apply --server-side --dry-run=server`. A subsequent API read confirms
  that dry-run did not persist a Deployment.

The runner retains raw API discovery, the server rejection, the persisted mock
notification, the modern dry-run response, and its command transcript under the
case evidence directory. The raw outputs contain only public Kubernetes schema
metadata and synthetic fixture content; no credentials or secret values are
collected.

## Source claim and coverage boundary

The official Kubernetes Deprecated API Migration Guide says Deployment APIs
`extensions/v1beta1`, `apps/v1beta1`, and `apps/v1beta2` stopped being served in
v1.16 and identifies `apps/v1` as the migration target, available since v1.9.
It also calls out required, immutable selectors in `apps/v1`; this fixture uses
matching selector and pod-template labels. The case checks that claim against
live v1.36.1 server discovery and server-side dry-run, rather than treating a
client-side schema check as cluster evidence.

This case validates one built-in resource mapping and a local mock tracking
record. It does not establish that a scanner finds every deprecated use across
all namespaces, running controllers, operator clients, Helm templates, CRDs,
custom resources, or CI repositories. Nor does it prove real ownership,
notification delivery, durable migration tracking, completion approvals,
upgrade authorization policy, or successful production upgrades. CRD field
deprecation semantics and mappings for other removed APIs remain untested and
require separate source review and cases.

Primary sources:

- [Kubernetes Deprecated API Migration Guide](https://kubernetes.io/docs/reference/using-api/deprecation-guide/)
- [Kubernetes `kubectl api-versions` reference](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_api-versions/)
- [Kubernetes Server-Side Apply](https://kubernetes.io/docs/reference/using-api/server-side-apply/)
- [Kubernetes `kubectl apply` reference](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_apply/)
