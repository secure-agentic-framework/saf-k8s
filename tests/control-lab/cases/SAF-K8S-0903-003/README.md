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
