# SAF-K8S-1001-012 — AI workload detection rule validation

This case is a defensive rule-logic demonstration for the six scenarios named in the pinned control. The runner creates a fresh disposable Kind cluster on Kubernetes v1.36.1 using the digest published by the Kind project. A small tokenless, non-root mock Pod uses a digest-pinned Python Official Image, emits one fixed benign JSON line, and makes no network requests. The case reads only that Pod's metadata and logs, its namespaced Kubernetes Events, and allowlisted metadata for its assigned Node. It writes `detection-validation.raw.json` with the bounded native observations and per-record decisions; the runner's `result.json` records independent red, green, and positive check outcomes.

The six rule checks use `fixtures/telemetry.json`, a static, fabricated, in-window set of metadata-shaped records and benign counters. Each rule has one alerting synthetic example and one approved/benign control. Thresholds and identity allowlist are explicit in the fixture. The records contain reserved `mock-*` object/workload labels and `system:serviceaccount:*:*-fixture` identities only. They contain no real events, targets, credentials, request contents, or attack execution. `fixtures/workload.py` is the only code run in the cluster; it prints a fixed marker and performs no network operation.

## Coverage and limits

- **InferenceService creation:** validates a synthetic audit-record predicate for unexpected principal versus expected owner. The KServe CRD is not installed; no real InferenceService event is generated.
- **GPU utilization without training:** validates a synthetic three-sample counter predicate. No GPU device, metrics exporter, training job, or utilization is present in Kind.
- **Training job changes:** validates synthetic PATCH/UPDATE actor-to-owner comparison. No training workload is modified.
- **Inference request rate:** validates a fabricated request counter threshold; no endpoint is deployed or called.
- **Model-storage egress:** validates a fabricated byte counter plus approved-window gate; no PV, model, egress path, packet, or network flow is observed.
- **Audit-policy ConfigMap changes:** validates a synthetic metadata record predicate. No audit policy is changed, and this check does not establish that an audit policy was evaded or that change contents are correct.
- **Native Kubernetes input:** confirms that Kubernetes API Events and Pod/Node metadata can be read and bound to the owned mock Pod in this disposable cluster. Kubernetes Events are best-effort supplemental data with limited retention, so they are not a substitute for API audit logs.

This case does not connect to or validate a SIEM, event forwarding, ingestion completeness, correlation scheduling, alert delivery, analyst response, production identity ownership, organization-specific thresholds, live attacker behavior, true positive rates, false positive rates, GPU telemetry, network egress observability, or production coverage. Passing demonstrates deterministic behavior on the named static fixtures and one bounded Kubernetes read path only. The supervisor must execute and review the two independent runs; this draft has not been run here.

## Unresolved control claims

The pinned statement says organizations “must” maintain these rules, and its rationale asserts that generic detections miss the named patterns. The Kubernetes and Kind sources below document Kubernetes event/audit behavior and the disposable cluster image; they do not establish that normative requirement, that generic SIEM rules fail, that each listed pattern is detectable from the named telemetry, or that the fixture thresholds/identity model are suitable for any organization. The case therefore records those as unverified source claims. Its predicates are illustrative test logic, not validated operational detections. In particular, “inference endpoint abuse,” “model exfiltration,” and “audit evasion” require richer service, flow, storage, and audit-policy evidence than this fixture supplies.

## Primary references

- [Kind v0.32 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0) publishes the `kindest/node:v1.36.1` digest and recommends digest pinning.
- [Kubernetes Event API](https://kubernetes.io/docs/reference/kubernetes-api/events/event-v1/) describes Events as informative, best-effort supplemental data with limited retention.
- [Kubernetes auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/) describes audit events and policy-controlled backends; this case's synthetic audit-shaped fixtures are not actual audit records.
- [Docker Official Images: Python](https://github.com/docker-library/official-images/tree/master/library) is the source repository for the Python Official Image used by the harmless mock Pod; the case pins its image digest.
