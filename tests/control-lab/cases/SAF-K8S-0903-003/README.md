# SAF-K8S-0903-003 — Inference-time resource controls

A digest-pinned Python Deployment serves fixed, benign requests through a
case-owned ClusterIP Service. The test waits for the current Ready Pod to be
the Service endpoint, submits ordinary synthetic work, and independently
checks HTTP outcomes and backend counters. It observes an exact 64-byte
input and a 65-byte UTF-8 input, request and cumulative session work limits,
a batch size gate, and distinct request, session, and batch deadlines. The
workload computes a bounded checksum only for accepted work. It chooses the
reduced-work response under the fixture's synthetic overload indicator.

The workload clock and capacity indicator are synthetic. The checks exercise
pre-work policy decisions and do not measure in-flight deadline interruption
or real overload. The test reads CPU and RAM limits from the Pod spec.
Production GPU memory isolation, circuit breakers, wall-clock timeouts,
and real cluster serving policy require separate deployment evidence.
