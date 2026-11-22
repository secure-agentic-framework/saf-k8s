# SAF-K8S-0901-002 — Parameter server and all-reduce security

## Executable slice

This draft exercises a narrow request-validation slice of the pinned control in a disposable Kind v0.32.0 cluster running Kubernetes v1.36.1. The node and every fixture Pod use digest-pinned images. It creates one case-owned ClusterIP aggregation endpoint, two synthetic worker clients, and a distinct observer client in one namespace. The endpoint has a fixed in-memory assignment table (`worker-a` and `worker-b` assigned to `round-7`) and a case-defined JSON schema: request ID, worker ID, assigned round, schema version, and a three-element finite numeric vector whose components are within `[-0.05, 0.05]`.

The red baseline starts the same mock with assignment and schema enforcement disabled. It receives only harmless, fixed small numbers: a correctly shaped request from an enrolled synthetic worker for the wrong round, and a short vector with two small numeric entries. Both are accepted by the mock, making the missing checks observable. The case captures these receipts and raw mock events, then replaces only the aggregator Pod with enforcement enabled. The Service address and client Pods remain the same. Green repeats the exact requests and expects one assignment rejection and one schema rejection. Positive checks send one ordinary assigned update from each worker. A separate observer Pod reads the exact mock output and accounting twice; the expected result is a mean vector of `[0.015, -0.01, 0.01]`, two accepted contributions, and stable counters of four requests, two accepts, and two rejects split by reason.

This is an authored toy protocol, not a training stack or a claim that this schema is a standard. The fixed output comes from accepted fixture vectors only. The endpoint does not use credentials, service account tokens, client certificates, real worker identity, a real model, or any training framework. The fixtures make no network calls except to the case-owned in-cluster Service. They do not log HTTP request lines, headers, credentials, or environment contents. Captured request/event evidence contains synthetic fixture IDs and the fixed numeric vectors only.

## Control claim coverage

| Pinned claim | Status in this case |
|---|---|
| Validate a contributed update's ordinary schema | **Demonstrated only for** the mock's fixed version, field set, vector length, numeric type, finiteness, and component range. Green rejects the two-element vector. |
| Check worker assignment for an aggregation round | **Demonstrated only for** the mock's static worker-to-round table. Green rejects an enrolled worker's request for a different round. This is not worker authentication or impersonation testing. |
| Stable accounting of rejected schemas and accepted contributions | **Demonstrated only for** the mock's in-memory per-process counters and two observer reads in one run. It does not test durable, concurrent, distributed, or tamper-resistant accounting. |
| Preserve aggregation output independent of worker receipts | **Demonstrated only for** an observer Pod's separate `GET /v1/mock-result`, exact expected arithmetic, and fixture-local accepted set. It is not a secure aggregation protocol or a production output-release boundary. |
| Gradient poisoning, backdoors, Byzantine fault injection | **Not tested.** There are no adversarial vectors or attack procedures. Small fixed values stay within the configured range. |
| Authenticated aggregation and worker impersonation prevention | **Not tested.** IDs are synthetic fields. No credentials, identity assertion, token, certificate, impersonation, or enrollment lifecycle is created. |
| Anomaly detection on update statistics | **Not tested.** The mock checks schema and assignment only; it has no anomaly model or signal. |
| Parameter server and all-reduce architectures | **Not tested.** The HTTP mock is neither architecture and does not establish topology coverage. |

The red result is the known permissive branch of this mock, not evidence that an external system is vulnerable. The green and positive outcomes establish only that the case-owned fixture rejects the specified two synthetic conditions and returns the expected arithmetic for its two accepted updates in this disposable cluster. Kubernetes scheduling, Service routing, and Pod readiness are setup evidence, not evidence for training-framework controls.

The pinned `control.md` states the poisoning, impersonation, Byzantine fault, backdoor, and model-quality claims as rationale but provides no supporting citations or implementation-specific evidence in that record. This case treats those claims as unresolved source assertions; it neither validates nor refutes them.

## Separate evidence obligations

The control's remaining claims require separately reviewed, implementation-specific evidence:

- Actual training frameworks, parameter-server deployments, and all-reduce implementations, including the exact worker-to-aggregator request paths and synchronous/asynchronous behavior.
- Production worker identity issuance, enrollment, assignment authorization, revocation, and transport authentication (including the projected service account token or SPIFFE/SPIRE configuration named by the control).
- The deployed Byzantine-resilient aggregation library and configuration, including its assumptions and behavior for the production topology.
- Gradient validation and anomaly signals as implemented in the real data path, with thresholds, telemetry, rejection actions, and operational review evidence.
- Model, training, backdoor, poisoning, and quality-impact claims. This case does not validate the control's source rationale about these effects.

No claim about any live framework, target, feed, training job, or production deployment is inferred from this mock. A passing supervisor run is not proof of complete control effectiveness.

## Running and evidence

From the control-lab root, the supervisor can run the case through the lab harness:

```sh
python3 lab.py test SAF-K8S-0901-002 --docker-context desktop-linux
```

The draft author did not run Docker, Kind, kubectl, Beads, or publishing. The supervisor should execute and review both red and enforced phases. The case writes bounded phase receipts, baseline and enforced mock event logs, two accounting reads, the independent exact result, and raw Service/Pod/EndpointSlice objects under the run's evidence directory. None of those files should contain credentials or Secret data.

## Official primary references

- [Kind v0.32.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0) — release and Kubernetes v1.36.1 node image provenance; the case pins `kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`.
- [Kind configuration](https://kind.sigs.k8s.io/docs/user/configuration/) — cluster configuration and node image selection.
- [Kubernetes Services](https://kubernetes.io/docs/concepts/services-networking/service/) — a Service provides a stable in-cluster endpoint for backing Pods; this case uses one selector-backed ClusterIP Service and checks its ready EndpointSlice.
- [Python 3.13 `http.server`](https://docs.python.org/3.13/library/http.server.html) and [`urllib.request`](https://docs.python.org/3.13/library/urllib.request.html) — standard-library HTTP server/client primitives used by the synthetic fixtures.
- [Docker Official Images source](https://github.com/docker-library/official-images/blob/master/library/python) — official Python image metadata; the case pins `docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90`.

Each contributor uses a Pod-bound, audience-scoped token checked by the live
Kubernetes TokenReview API. The reviewer can only create TokenReview objects.
The observer authenticates as itself and is denied contribution because it
has no enrollment. Both cohorts send only fixed inert fixture data, and the
transcript excludes tokens. The range boundary is tested using one ordinary
value just outside the documented fixture limit.

- [Kubernetes ServiceAccount token projection and verification](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/)
