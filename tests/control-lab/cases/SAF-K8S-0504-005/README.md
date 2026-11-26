# SAF-K8S-0504-005 Istio proxy tuning

`python3 tests/control-lab/lab.py test SAF-K8S-0504-005 --docker-context desktop-linux`

The disposable cluster installs the pinned Istio configuration used in
SAF-K8S-0504-001. Strict mTLS protects the local fixture Service. The baseline
reads the default proxy resources and records three exact authenticated
requests. Recreating just the backend with explicit proxy CPU and memory
requests and limits changes its rendered proxy configuration. The same
client receives three exact responses after tuning.

A server dry-run refuses a candidate whose proxy request exceeds its limit.
The exact known-good backend still serves authenticated fixture requests.
Peak throughput, latency, GPU behavior, actual ingress hardening, and
approved training exceptions need separate deployment evidence.

## Paired reference proof

The actual lab receipt `saf-k8s-control-lab/evidence/SAF-K8S-0504-005/20261124T020606Z-8d078f96/result.json` and independent framework receipt `saf-k8s-framework/tests/control-lab/evidence/SAF-K8S-0504-005/20261124T020852Z-29917e24/result.json` each pass 6 checks on separate disposable Kubernetes v1.36.1 Kind clusters and report cleanup `deleted`. Both use the adjacent fixture's pinned Istio 1.32.0 sidecar profile.

The six checks establish: pinned cluster and Istio readiness; three baseline authenticated GETs and the default injected proxy request/limit values; exact Istio proxy CPU/memory annotation rendering into the tuned Pod; three successful authenticated GETs after tuning; and rejection by API server-side dry-run of a candidate whose proxy CPU request exceeds its limit while the known-good Pod UID/resources and 3/3 requests remain unchanged.

This is an adequate portable witness for the documented Istio resource-annotation mechanism, reading effective proxy resource values, maintaining a small owned authenticated route, and preflighting an invalid resource configuration without changing the known-good Pod. It is not a performance benchmark and the dry-run is a pre-admission guard, not a failed live rollout followed by rollback. It does not collect CPU/memory usage, throttling, OOM or pod eviction data; measure mTLS overhead, latency or throughput; use a GPU/NCCL workload; test inference ingress hardening; or retain mesh metrics/traces. The fixture's access-log checks prove the test request passed through an authenticated proxy, not durable telemetry coverage.

## Scope disposition

The broad control statement and open child `saf-lab-0504-005.1` require actual throughput/latency comparisons, proxy and mesh resource measurements, accelerator/NCCL paths, exemptions/compensating controls, inference ingress protections, and rollout/rollback evidence. These depend on the adopting workload, hardware, SLOs, mesh topology, and production telemetry; they are appropriate owner evidence. A generic Kind load or GPU simulation would not close these deployment claims. No additional portable runtime is needed for the annotation-rendering guard already proven.

The 34 current NIST crosswalks do not accurately map this narrow case. The closest row, SA-8(26) Performance Security, has no observed performance metric or workload measurement here; a three-request availability sample is not a performance evaluation. SC-8/mTLS is an inherited adjacent mechanism and has its own 0504-002 evidence. The remaining crosswalk notes concern identity propagation, crypto transport, architecture, trust federation, anti-spoofing, protocol validation, or message visibility not established by this tuning case. The exact tuple plan therefore proposes removal of all 34 current rows without adding replacements. Restore an applicable mapping only after attaching evidence for its actual requirement.

## Owner-side evidence procedure

1. **Set the workload and acceptance envelope.** Identify the service, model/training or inference phase, node/GPU type, replica layout, expected request or collective pattern, and relevant SLOs. Select a representative non-production workload and a repeatable data size/rate. Define acceptable throughput, p50/p95/p99 latency, GPU utilization, error rate, and resource ceiling before tuning.
2. **Capture the deployed baseline.** Record exact Kubernetes/Istio versions and dataplane mode; the effective injected proxy requests/limits; per-proxy CPU and memory working set, CPU throttling, restarts/OOMs; app CPU/memory; GPU utilization; and NCCL or inference throughput/latency where relevant. Preserve a time-aligned workload and mesh telemetry window and identify its source, labels, sampling/retention, and gaps.
3. **Change one mesh resource dimension at a time.** Record the reviewed workload-template change and resulting actual `istio-proxy` container resources after injection. Confirm the intended proxy/mesh configuration is reconciled and ready, then run the same authorized workload profile and acceptance metrics. Compare the result to the declared baseline and SLO; document the selected value and reason.
4. **Keep the security path intact.** Confirm the effective peer-authentication and authorization configuration for the measured workload. Do not disable production mTLS or remove the proxy to manufacture a performance comparison. If an explicitly approved training exception exists, record the exact workload/paths, approving owner, duration/review date, compensating protection, and the separate evidence that the protection covers the same-node and cross-node traffic in scope.
5. **Retain a safe update path.** Preserve the last known-good workload template and bounded rollout/rollback decision criteria. Record a real owner-approved staging rollout's observed new Pod resources, readiness, request availability, mesh policy/telemetry status, and rollback action if a threshold fails. The portable server-side dry-run only checks that an invalid request/limit pair is rejected; it is not rollout evidence.
6. **Keep inference ingress separate and attributable.** For model-serving ingress, retain the actual gateway/ingress configuration and owner-approved evidence for authentication, request/response size bounds, rate limits, and input schema constraints. Capture configuration and ordinary sanitized telemetry; this tuning fixture does not test those controls or attack scenarios.

## Official versioned Istio references

- [Istio 1.32 sidecar injection and resource customization](https://istio.io/v1.32/docs/setup/additional-setup/sidecar-injection/): proxy resource annotations, explicit paired CPU/memory requests and limits, and injected-Pod verification.
- [Istio 1.32 resource annotation reference](https://istio.io/v1.32/docs/reference/config/annotations/): `proxyCPU`, `proxyCPULimit`, `proxyMemory`, and `proxyMemoryLimit` meanings and feature status.
- [Istio 1.32 performance and scalability](https://istio.io/v1.32/docs/ops/deployment/performance-and-scalability/): workload-dependent measurement factors for latency, throughput, CPU and memory; its published sample numbers are tied to the stated test environment/version and are not substitutes for adopter measurements.
