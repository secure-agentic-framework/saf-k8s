# SAF-K8S-1007-007 — Shared service guardrails under synthetic workload admission

Run with the lab supervisor's normal two-run verification for the pinned case. The case targets a fresh disposable Kind v1.36.1 cluster using the runner’s pinned node image. The runner provisions and cleans up the cluster.

The case records distinct admission observations:

- **Red:** before a namespace ResourceQuota exists, a server-side dry-run of a 16m CPU / 24Mi synthetic Pod is admitted.
- **Green:** after setting `requests.cpu: 20m` and `requests.memory: 32Mi`, the same request is refused: the steady fixture uses 5m / 8Mi, so aggregate CPU requests would be 21m against a 20m cap. A separate 15m / 25Mi request is refused by the memory cap.
- **Positive:** a server-side dry-run request of 15m / 24Mi is admitted at the remaining declared budget. Its Pod readback resolves the training PriorityClass to value 10 with `preemptionPolicy: Never`.

The case also creates two case-owned PriorityClasses (shared health fixture value 1000; training probe value 10), both non-preempting and not global defaults. It reads back their values and the effective priority fields on each Pod. A tokenless Python HTTP fixture requests 5m CPU / 8Mi memory, stays Ready, and serves the fixed `healthz.txt` marker through a Kubernetes API Service proxy before and after the quota probes. All synthetic objects use `saf-lab.example` labels and the namespace provided by the lab runner.

Raw command and API output is retained by the existing lab runner in the per-run evidence directory. Inputs and outputs are limited to the fixed synthetic fixture, Kubernetes metadata, quota refusal detail, and health marker; the case creates or reads no credentials, external feed, or real target data.

## Source claims and limits

Kubernetes documents that ResourceQuota tracks aggregate namespace requests and rejects requests that exceed a hard limit; PriorityClass maps a name to an integer where a higher value denotes higher priority; `preemptionPolicy: Never` prevents a Pod from preempting lower-priority Pods while still placing it earlier in the scheduling queue. Readiness probes and the Pod status provide the fixture's health readback. The case observes API admission, class resolution, Ready status, and one HTTP fixture response. It does not create pending Pods or resource contention, so it does **not** establish observed scheduler queue order, service protection under load, or that this priority policy is safe for a real cluster. Kubernetes built-in `system-cluster-critical` / `system-node-critical` policy is not changed or asserted.

A fixed lookup through the Pod’s DNS configuration resolves the exact in-cluster Kubernetes Service before and after the quota probes. The native observations are point checks. Production DNS latency, logging, metrics pipelines, node/network capacity, actual training behavior, and service availability under real workload require independent verification. Resource requests and quotas constrain declared requests; they do not prove runtime consumption or prevent all forms of capacity pressure. In particular, the rationale names network bandwidth exhaustion, while this case and the cited ResourceQuota API exercise CPU and memory requests only; bandwidth protection needs a separately identified and verified mechanism.

The control's NIST crosswalk and framework mapping notes are catalog assertions, not evidence produced by this case. Their applicability to this specific quota, priority, and health-monitoring statement remains a separate source review; this case does not infer technical support from the mappings.

- [Kubernetes v1.36 ResourceQuota](https://v1-36.docs.kubernetes.io/docs/concepts/policy/resource-quotas/)
- [Kubernetes v1.36 Pod Priority and Preemption](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/pod-priority-preemption/)
- [Kubernetes v1.36 readiness probes](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/)
- [Kind v1.36.1 release and node image digest](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0)
- [Docker Official Python image](https://hub.docker.com/_/python)

The case preserves its quota and health readbacks in `quota-health-observations.raw.json`.
