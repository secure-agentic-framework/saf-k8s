# SAF-K8S-0901-002 — Parameter server and all-reduce security

## Executable slice

This draft exercises a narrow request-validation slice of the pinned control in a disposable Kind v0.32.0 cluster running Kubernetes v1.36.1. The node and every fixture Pod use digest-pinned images. It creates one case-owned ClusterIP aggregation endpoint, two synthetic worker clients, and a distinct observer client in one namespace. The endpoint has a fixed in-memory assignment table (`worker-a` and `worker-b` assigned to `round-7`) and a case-defined JSON schema: request ID, worker ID, assigned round, schema version, and a three-element finite numeric vector whose components are within `[-0.05, 0.05]`.

The red baseline starts the same mock with assignment and schema enforcement disabled. It receives three harmless fixed requests: a correctly shaped request from an enrolled synthetic worker for the wrong round, a short vector, and an out-of-range vector. Each receives the permissive mock's accepted response; only safely shaped, in-range values enter its arithmetic. The case captures these receipts and raw mock events, then replaces only the aggregator Pod with enforcement enabled. The Service address and client Pods remain the same. Green repeats the requests and expects one assignment rejection and two schema/range rejections. The un-enrolled observer is rejected separately before contribution accounting. Positive checks send one ordinary assigned update from each worker. A separate observer Pod reads the exact mock output and accounting twice; the expected result is a mean vector of `[0.015, -0.01, 0.01]`, two accepted contributions, and stable counters of five enrolled-worker requests, two accepts, and three rejects split by reason.

This is an authored toy protocol, not a training stack or a claim that this schema is a standard. The fixed output comes from accepted fixture vectors only. The original HTTP case uses projected, audience-scoped Pod service-account tokens and Kubernetes TokenReview for synthetic workers, as described below; the additive supplement uses PyTorch only for one fixed CPU collective. Neither uses external credentials, real worker identity, a real model, or training data. The fixtures make no network calls except to case-owned in-cluster Services and the Kubernetes API for the configured TokenReview operation. They do not log HTTP request lines, headers, tokens, credentials, or environment contents. Captured request/event evidence contains synthetic fixture IDs and fixed numeric vectors only.

## Control claim coverage

| Pinned claim | Status in this case |
|---|---|
| Validate a contributed update's ordinary schema | **Demonstrated only for** the mock's fixed version, field set, vector length, numeric type, finiteness, and component range. Green rejects the two-element vector. |
| Check worker assignment for an aggregation round | **Demonstrated only for** the mock's static worker-to-round table. Green rejects an enrolled worker's request for a different round. This does not establish production assignment governance. |
| Stable accounting of rejected schemas and accepted contributions | **Demonstrated only for** the mock's in-memory per-process counters and two observer reads in one run. It does not test durable, concurrent, distributed, or tamper-resistant accounting. |
| Preserve aggregation output independent of worker receipts | **Demonstrated only for** an observer Pod's separate `GET /v1/mock-result`, exact expected arithmetic, and fixture-local accepted set. It is not a secure aggregation protocol or a production output-release boundary. |
| Gradient poisoning, backdoors, Byzantine fault injection | **Not tested.** There are no adversarial vectors or attack procedures. Small fixed values stay within the configured range. |
| Authenticated aggregation and worker impersonation prevention | **Demonstrated only for** synthetic Pod-bound audience-scoped service-account tokens checked by Kubernetes TokenReview, static fixture enrollment, and rejection of an authenticated but unenrolled observer. It does not establish production worker identity issuance, enrollment lifecycle, revocation, transport authentication, or impersonation defenses in an adopted training stack. |
| Anomaly detection on update statistics | The original 14 checks do not cover it. The screening check compares one explicitly declared deterministic threshold policy against a screening-off counterfactual using the same three harmless in-range vectors; it is not an anomaly model or evidence of production thresholds. |
| Parameter server and all-reduce architectures | The original HTTP mock is neither architecture. The additive supplement below exercises one fixed two-rank CPU Gloo SUM only; it does not establish training topology coverage. |

The red result is the known permissive branch of this mock, not evidence that an external system is vulnerable. The green and positive outcomes establish only that the case-owned fixture rejects the specified synthetic conditions and returns the expected arithmetic for its accepted updates in this disposable cluster. The added screening-off/screening-on comparison establishes only its exact fixed fixture policy. Kubernetes scheduling, Service routing, and Pod readiness are setup evidence, not evidence for training-framework controls.

The control statement requires authenticated aggregation, gradient validation, and anomaly detection, while its rationale discusses poisoning, impersonation, Byzantine faults, backdoors, and model-quality effects. This fixture provides only synthetic identity, assignment/schema checks, and the separately scoped threshold-policy supplement below; it neither validates nor refutes the control's model-specific rationale.

## Separate evidence obligations

The control's remaining claims require separately reviewed, implementation-specific evidence:

- Actual training frameworks, parameter-server deployments, and all-reduce implementations beyond the one fixed CPU Gloo operation below, including exact production request paths and synchronous/asynchronous behavior.
- Production worker identity issuance, enrollment, assignment authorization, revocation, and transport authentication (including the projected service account token or SPIFFE/SPIRE configuration named by the control).
- The deployed Byzantine-resilient aggregation library and configuration, including its assumptions and behavior for the production topology.
- Gradient validation and anomaly signals as implemented in the real data path, with thresholds, telemetry, rejection actions, and operational review evidence.
- Model, training, backdoor, poisoning, and quality-impact claims. This case does not validate the control's source rationale about these effects.

## Bounded synthetic in-range screening supplement

The case preserves the 14 original assertions and compares the
same three fixed, valid, in-range vectors under a `screen-off` variant and a
separate `screen` policy variant. Schema and worker-round assignment checks
remain enabled in both; only the anomaly screening policy changes. In the
screen-off counterfactual, all three receive accepted responses and appear in
its independently read aggregate, with three accepted and zero rejected. The
existing projected audience-scoped worker identity and Service path remain
in use in both variants. The vectors are evaluated against the declared synthetic baseline
`[0.01, -0.01, 0.0]` using the maximum absolute coordinate
deviation rounded to eight decimal places. Scores at or below `0.015` are
accepted; scores above `0.015` and below `0.03` raise an alert and are
quarantined from aggregation; scores at or above `0.03` are denied. The
benign boundary comparator has score `0.015`, the alert fixture `0.02`, and the
deny fixture `0.03`. In screening mode the expected counters are three received,
one accepted, one quarantined/alerted, and one denied; the independent
aggregate contains only the accepted comparator. The one added assertion
requires the exact same observed request bodies in both modes and compares
their independent status and aggregate readbacks.

These fixed values are ordinary numeric examples, not generated malicious
training inputs. The test checks only this authored deterministic fixture
policy; it does not validate a learned anomaly detector, a statistical
distribution, real model-specific thresholds, false-positive rates, poisoning
or Byzantine resistance, or deployment response. The case includes 19 checks, including the two CPU Gloo checks below.
Screening-off receipts are written as `screening-off-policy.raw.json` and
related `screening-off-*` files; screening receipts use `screening-policy.raw.json`
and related screening request/readback files under the evidence directory.

No claim about any live framework, target, feed, training job, or production deployment is inferred from this mock. A passing supervisor run is not proof of complete control effectiveness.

## Running and evidence

From the control-lab root, the supervisor can run the case through the lab harness:

```sh
python3 lab.py test SAF-K8S-0901-002 --docker-context desktop-linux
```

Review the original red and enforced phases and the comparison with screening disabled and enabled. The case writes bounded phase receipts, original baseline and enforced mock event logs, paired screening event logs, independent accounting/aggregate reads, and raw Service/Pod/EndpointSlice objects under the run's evidence directory. No raw artifact should contain tokens, credentials, or Secret data.

## Official primary references

- [Kind v0.32.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0) — release and Kubernetes v1.36.1 node image provenance; the case pins `kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`.
- [Kind configuration](https://kind.sigs.k8s.io/docs/user/configuration/) — cluster configuration and node image selection.
- [Kubernetes Services](https://kubernetes.io/docs/concepts/services-networking/service/) — a Service provides a stable in-cluster endpoint for backing Pods; this case uses one selector-backed ClusterIP Service and checks its ready EndpointSlice.
- [Python 3.13 `http.server`](https://docs.python.org/3.13/library/http.server.html) and [`urllib.request`](https://docs.python.org/3.13/library/urllib.request.html) — standard-library HTTP server/client primitives used by the synthetic fixtures.
- [Docker Official Images source](https://github.com/docker-library/official-images/blob/master/library/python) — official Python image metadata; the case pins `docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90`.

Each contributor uses a Pod-bound, audience-scoped token checked by the live
Kubernetes TokenReview API. The reviewer can only create TokenReview objects.
The observer uses its own projected identity for a contribution attempt and is
denied because it has no enrollment; the fixture's status/result GET endpoints
are readable without HTTP authentication. All Pods use synthetic service
accounts, fixed inert values, and the transcript excludes tokens. The original
range boundary is tested using one ordinary value just outside the fixture limit.

- [Kubernetes ServiceAccount token projection and verification](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/)

## TLS-only worker channel reference

The published 17-check case includes an isolated second aggregator endpoint using the same case-owned TokenReview handler behind a TLS-only listener. An ephemeral test CA issues a server certificate whose DNS SAN exactly matches the primary Service and a second certificate signed by that same CA for a separate alternate Service name. Private keys exist only in a temporary host directory and as short-lived mounted Secrets in the disposable cluster; the fixture writes no key bytes or certificate private material to logs or evidence.

The worker sends one fixed, ordinary in-range vector over HTTPS after validating the CA and primary Service DNS name. It first issues a body-free cleartext health request to the TLS port, which must fail before a contribution arrives. The accepted TLS contribution is then checked through a separate TLS status and aggregate readback. For the identity comparator, the alternate-name certificate is independently verified as CA-trusted for its own DNS name; using it at the primary Service name must fail hostname validation before the client sends the contribution. The same endpoint remains available through the alternate Service name for a verified read-only status check showing no contribution was processed.

The receipt covers the case-generated TLS channel and its application-level TokenReview identity. Verify production certificate issuance and rotation, the deployed training runtime, and the required parameter-server or collective communication paths under the adopter profile.

## Two-rank CPU collective

The additive `gloo_collective.py` hook follows the existing 17 assertions. It
removes the original worker client Pods after those checks, then runs two new
case-owned Pods using the same synthetic `worker-a` and `worker-b` service
accounts and projected audience-scoped tokens. Both submit the same valid fixed
vectors already used by the published case to the same TokenReview, assignment,
and schema handler. A small subclass reuses that handler's `review_token`,
`ASSIGNMENTS`, and `/v1/contribute` implementation; its only additional route
returns a fixed rank after TokenReview and assigned-round validation.

The runner builds and imports a CPU runtime using the case's hash-locked
wheel set and an offline Docker build. The module checks PyTorch `2.15.0+cpu`
and Gloo availability in each worker. The two Pods perform exactly one
length-three `torch.distributed` Gloo SUM each, with a 30-second process-group
timeout. Their expected sum is `[0.03, -0.02, 0.02]`; the expected mean remains
the published mock result `[0.015, -0.01, 0.01]`. Resource requests/limits are
bounded to 250m/500m CPU and 512Mi/1Gi memory per worker. The reducer is not a
model or training loop.

This checks the library collective on two legitimate enrolled worker Pods. It
does not make Gloo authenticate peers or prove that the deployed network path
matches this case. Production peer authentication, worker identity lifecycle,
real collective membership controls, framework topology, robust aggregation,
gradient anomaly behavior, and model-quality outcomes remain adopter evidence.
The two additive checks require exact rank/admission events and the same
independent sum on both completed Pods. Raw results contain only fixed numeric
vectors, worker names/ranks, scoped Pod metadata, runtime version/backend, and
wheel hashes. The case keeps tokens and credentials out of the evidence.
Set
`SAF_GLOO_WHEEL_CACHE` to a local directory to reuse reviewed wheel downloads.
The builder verifies the size and digest of every cached wheel. The case
uses the official [PyTorch distributed
API](https://docs.pytorch.org/docs/stable/distributed.html) and the CPU Gloo
backend; PyTorch's [Distributed Data Parallel documentation](https://docs.pytorch.org/docs/stable/notes/ddp.html)
describes its Gloo process group and all-reduce path. These references support
the library behavior exercised here, not an adopter's complete training
configuration.
