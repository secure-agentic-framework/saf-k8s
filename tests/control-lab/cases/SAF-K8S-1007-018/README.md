# SAF-K8S-1007-018 — Deprecated API inventory and migration tracking

Run from the SAF-K8S framework root with:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1007-018 --docker-context desktop-linux
```

The runner creates a disposable Kind v1.36.1 cluster using the digest-pinned
`kindest/node` image in `case.py`. The fixtures are owned synthetic Deployment
manifests: `extensions/v1beta1` and its documented `apps/v1` replacement. Their
mock container image uses the reserved `.invalid` domain, has zero replicas, and
is never started. Helm is also required to render the local chart fixture.

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

The native CRD comparison also renders the old and revised Helm chart, observes
an actual warned request, delivers the exact attributed finding to a tokenless
fixture inbox reader, and disables the old served version. The stable path still
serves the same object and payload. This is a serving transition for an object
already stored as v1.

## Verify your implementation

1. Record the current and proposed Kubernetes versions and the inventories in the
   change scope. Include AI workload namespaces, source and rendered manifests,
   Helm releases and hooks, installed operators and external clients, APIService
   registrations, and custom resources. Preserve artifact revision, chart and
   values digests, operator version, and cluster identity.
2. Render charts with the target's Kubernetes version and API capabilities,
   including applicable CRDs and hooks. Discover live API support with
   `kubectl --context "$SAF_CONTEXT" api-resources --cached=false -o wide`.
   Compare discovery with rendered API references and observed requests.
   Collect deprecated-request warnings, audit and request telemetry where
   available. Record the collection window, caller, exact resource and blind
   spots. Discovery tells you what is served. Request evidence shows observed use.
3. For CRDs, inspect `spec.versions` for served, deprecated and storage values
   and `status.storedVersions` for persisted-version evidence. Exercise
   supported conversion and storage migration on the target before retiring
   a version that still has persisted objects. Verify field changes against
   the provider or CRD owner's version-specific schema and migration guide.
4. Create or update the change record for each affected caller or artifact.
   Keep the exact target, old and replacement API, owner, received notification
   or acknowledgment, planned cutover, source and target behavior evidence, and
   migration outcome. A collector gap or unassigned finding keeps approval on hold.
5. Validate the replacement against a disposable target with the intended
   policy, operators and integrations. Reconcile the tracked inventory to the
   tested revision and exercise blocked and allowed upgrade decisions. Keep
   the deployment approver and delivery evidence for the exact candidate.

Primary sources:

- [Kubernetes Deprecated API Migration Guide](https://kubernetes.io/docs/reference/using-api/deprecation-guide/)
- [Kubernetes `kubectl api-versions` reference](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_api-versions/)
- [Kubernetes Server-Side Apply](https://kubernetes.io/docs/reference/using-api/server-side-apply/)
- [Kubernetes `kubectl apply` reference](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_apply/)

- [Kubernetes CRD versioning](https://v1-36.docs.kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definition-versioning/)
