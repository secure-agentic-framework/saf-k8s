# SAF-K8S-1001-007 — Application events and mesh access metadata

Run from the lab checkout.

```sh
python3 lab.py test SAF-K8S-1001-007 --docker-context desktop-linux
```

From the framework checkout invoke `python3 tests/control-lab/lab.py`.
The disposable Kubernetes API logs only Metadata for a fixture request.
A live synthetic application writes a separate allowlisted inference event
with supplemental collection enabled. With collection disabled the matching
event is absent. The fixture retains the control decision and exact event
shape with the model and version set to fixed fixture values.

The separate in-cluster case installs pinned Istio 1.32.0. Its owned
receiver replies 204 only when a single fixed POST carries the expected
body and correlator. The destination Envoy sidecar records the method, path,
status, correlator, and exact request and response byte counts. The observed
access-log line contains no fixture body marker. The result retains the
predicates used for the comparison.

## Verify the adopted telemetry

1. Inventory the application and runtime events needed for the deployed
   model loaders, inference and GPU workload paths. Record selected event
   and identity fields, the supported mesh or application emitter, the
   authorized collection path and the consumer.
2. Use separate owned markers to verify an API audit event, an application
   event and proxy metadata. Compare observed fields for the same request.
   At each layer enforce the approved schema and check that payload markers
   outside that schema are absent from retained output. Authorize and test
   any application payload fields separately under the applicable data policy.
3. Exercise a real model load and inference operation on a representative
   workload when verifying those events. For GPU process events, reconcile
   supported process and device identifiers, workload ownership,
   completeness and dropped events against an independent inventory.
4. Verify forwarding to the intended collector, restricted retrieval and
   retention. Observe an approved collector-loss/recovery scenario,
   correlate one exact event through storage and read-back, and retain
   evidence for required protective controls and alerting.

[Istio access logging](https://istio.io/latest/docs/tasks/observability/logs/access-log/)
and [Envoy v1.32 access log fields](https://www.envoyproxy.io/docs/envoy/v1.32.0/configuration/observability/access_log/usage).
The model-load check uses Kubernetes v1.36's [Downward API](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/pods/downward-api/), [ServiceAccount projected credentials](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/), [RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/), and [audit logging](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/) to bind an inert artifact receipt to the actual case Pod identity.

## Inert model-artifact load attribution reference

The eleven-check case includes one separately observed model-load event. A
case-owned Pod opens a small fictional JSON model descriptor mounted from an
immutable ConfigMap, calculates its digest, and writes a minimized
`model_artifact_loaded` event through the Kubernetes API using its projected
ServiceAccount token. The Role permits `patch` only
to one named receipt ConfigMap. An independent harness read checks the persisted
event against the created Pod UID, namespace, exact ServiceAccount, artifact
digest and the process log; the receipt's Kubernetes object UID must remain
stable. A scoped native API audit record independently identifies the exact
ServiceAccount that patched the receipt, at Metadata level without request or
response bodies. Tokens and credentials are never printed or included in evidence.

Four layers of evidence link the fixture file, process log, API receipt and
API audit identity. Actual serving-framework loader behavior, production
models, GPU activity, downstream delivery and retention require adopter evidence.
For adopters, capture the real loader event and artifact identity, bind it to
the workload's authenticated identity, and reconcile source and collector
receipts. Treat GPU process and provider telemetry separately and validate it
against supported device/runtime sources.

## Native CPU model serving

The native check confirms a successful model-load event, the pinned model bytes read inside the running server container, and a bounded completion from the same Pod. Pod, container and image identities are checked around the hash and request. Run from the complete control-lab checkout with the adjacent SAF-K8S-0903-004 case. See [the native event evidence and scope](NATIVE-EVENT-SCOPE.md) for the Docker/CRI config-ID distinction.

## Native inference metadata correlation

The case labels only `saf-test` for injection before it creates the native
test server and client. It pins the
Istio proxy image on both Pods and creates one case-owned ClusterIP Service
whose selector matches the native server Pod. An EndpointSlice read must show
exactly one Ready endpoint with that exact server Pod UID before the request.
The existing tiny CPU model receives one additional fixed `/completion`
request through that Service with `X-SAF-Case: SAF1001-NATIVE-INFER-001`.
The client emits only HTTP status, native predicted-token count, stop reason,
request and response byte counts, and the fixed correlator; it does not print or persist
prompt or completion text.

The destination `istio-proxy` log must contain exactly one seven-field,
metadata-only record matching `POST /completion`, HTTP 200, positive byte
counts and the same correlator. The normalized check also binds the record to
the Ready Service endpoint, pinned proxy images, and the same native server
Pod UID and image identity whose model digest the preceding check verified.
The paired 12-check receipt includes this local CPU-only request-path
correlation. Raw evidence is stored in `native-inference-mesh-correlation.json`.
Adopters verify actual mesh policy, GPU telemetry, sustained traffic,
collector forwarding, retention and alert handling.

- [Istio access logging](https://istio.io/latest/docs/tasks/observability/logs/access-log/)
- [Envoy v1.32 access log operators](https://www.envoyproxy.io/docs/envoy/v1.32.0/configuration/observability/access_log/usage)
