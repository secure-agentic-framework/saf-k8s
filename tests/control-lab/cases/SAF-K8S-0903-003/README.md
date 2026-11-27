# SAF-K8S-0903-003 — Inference-time resource controls

A digest-pinned Python Deployment serves fixed, benign requests through a
case-owned ClusterIP Service. The test waits for the current Ready Pod to be
the Service endpoint, submits ordinary synthetic work, and independently
checks HTTP outcomes and backend counters. It observes an exact 64-byte
input and a 65-byte UTF-8 input, request and cumulative session work limits,
a batch size gate, and distinct request, session, and batch deadlines. The
workload computes a bounded checksum only for accepted work. It chooses the
reduced-work response under the fixture's synthetic overload indicator.

The original policy fixture's clock and capacity indicator are synthetic. Its
three checks exercise pre-work policy decisions and do not establish a real
inference engine's in-flight cancellation or actual overload handling. The test
reads CPU and RAM limits from the Pod spec. Production GPU memory isolation,
circuit breakers, model-server timeout behavior, and real cluster serving policy
require separate deployment evidence.

Kubernetes GPU extended-resource requests and ResourceQuota govern device counts. For an actual GPU-memory ceiling, verify the deployed GPU model, sharing or partition profile and runtime enforcement, including independent measurement under controlled authorized pressure. Confirm CPU and host-memory limits separately.

## Bounded elapsed-deadline supplement

The additive `deadline_supplement.py` runs a separate case-owned HTTP worker and
client in the same disposable cluster. The worker performs no model or external
work: it processes at most eight fixed SHA-256 work units per request, each
followed by a 15 ms fixture pacing interval. It uses `time.monotonic()` and
checks request, cumulative-session, and batch deadlines between units. The
finite client sends fixed requests with 45 ms request and batch budgets and a
120 ms cumulative session budget. For each scope it records an over-budget
request that is interrupted after some work, backend counter deltas matching
the completed units, and a separate in-budget comparator that completes.
Further work in an expired session is rejected with zero additional units.

This proves cooperative elapsed-deadline behavior in this inert HTTP worker,
including an actual work-stop point and independent counters. It does not
interrupt an individual work unit, establish hard real-time guarantees, or
validate model-server, GPU, service-mesh, cloud-cost, production overload, or
circuit-breaker behavior. The pre-existing virtual-deadline and synthetic
degradation observations remain independent evidence.

## Bounded circuit-breaker reference supplement

The additive circuit_breaker_supplement.py creates an immutable ConfigMap and
runs circuit_breaker_job.py in one bounded Kubernetes Job. The Job uses the
same digest-pinned Python image as the published fixture, a read-only source
mount, no service-account token, non-root UID/GID 65534, a read-only root
filesystem, dropped capabilities, and fixed CPU/memory limits. The breaker,
fixed-response backend, and probe all execute inside that Job's Pod. The
backend binds only to that Pod's loopback interface; no Service or external
request is used. The harness reads the Job's exact owned Pod, successful
container exit, and single JSON observation from its logs.

The worker sends exactly four backend requests: two controlled 503 responses
to reach the configured threshold, one healthy half-open probe, and one
recovery request. An open request and a competing request during the
in-flight half-open probe are rejected without incrementing the backend call
count. The finite cooldown and probe hold are fixed in the fixture, and server
threads are stopped before Job exit.

This adds one local state-machine assertion. It is not production middleware,
a service-mesh or deployed model-server circuit breaker, and it does not show
that a real inference path uses this behavior. The original six assertions
and their Kubernetes fixture remain unchanged.
