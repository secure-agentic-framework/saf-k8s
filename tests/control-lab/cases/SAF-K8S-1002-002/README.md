# SAF-K8S-1002-002 — Distributed tracing for ML pipelines

```sh
python3 lab.py test SAF-K8S-1002-002 --docker-context desktop-linux
```

From the framework checkout, use `python3 tests/control-lab/lab.py` with the same arguments. A disposable Kubernetes v1.36.1 Kind cluster runs a digest-pinned OpenTelemetry Collector and synthetic ingestion, registry, and inference services. The workloads install the pinned OpenTelemetry SDK packages from PyPI. Each native training Job forwards W3C context as part of the fixture workflow.

The case verifies actual Collector output. Without the injected context, the training Job completes and starts its own trace. With the context, the Collector records the exact ingestion, training, registry, and inference parent IDs as one tree. A tagged synthetic error belongs to the intended inference span. A separate healthy workflow produces a complete, independent trace.

For deployment, verify the actual orchestrators and InferenceService annotation handoffs, instrumentation coverage, sampling, retention, backend durability and use in incident response.

[W3C Trace Context](https://www.w3.org/TR/trace-context/) · [OpenTelemetry Python propagation](https://opentelemetry.io/docs/languages/python/propagation/) · [OpenTelemetry Collector 0.136.0](https://github.com/open-telemetry/opentelemetry-collector-releases/releases/tag/v0.136.0)

The KServe v0.21.0 extension uses Standard mode and its generated internal
Service. It tests KServe carrying the configured W3C annotation into the predictor
Pod. The actual native Job and predictor use the Python OpenTelemetry SDK to
extract and export trace context. The same Collector observes the linked native
Job and KServe trace and an independent no-context predictor trace.

## Deployed adopter evidence

1. Inventory pipeline components and versions from data ingestion through training, registry and inference. Record how trace context is propagated across synchronous and asynchronous boundaries, including any KServe annotation or orchestrator-specific mechanism.
2. Demonstrate approved, representative end-to-end traces from each deployed stage. Retain trace IDs and parent/span relationships, source/destination component versions, sampling decisions and a benign no-context comparator. Use policy-safe synthetic or authorized operational events.
3. For MEASURE 2.3, name the AI performance/assurance criterion (for example, a defined latency or availability threshold), its instrument, evaluation method, relevant deployment conditions, observed result and limitations. Tracing alone is not the metric.
4. Verify trace backend retention/durability, query access, identity and timestamp quality, redaction of sensitive fields, sampling loss, outage behavior and incident retrieval using the deployed provider/backend configuration.
5. If claiming production monitoring or alerting, attach exact current runtime rule/alert revisions, delivery receipts and analyst review records. This case creates no alert or SIEM event.
6. Reconcile the exact current case and control fingerprints before carrying forward prior lab/framework receipts.

## Primary sources

- NIST AI 100-1, Table 3, MEASURE 2.3: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf
- W3C Trace Context: https://www.w3.org/TR/trace-context/
- OpenTelemetry Python propagation: https://opentelemetry.io/docs/languages/python/propagation/
- OpenTelemetry Collector 0.136.0: https://github.com/open-telemetry/opentelemetry-collector-releases/releases/tag/v0.136.0

For an applicable high-risk AI system, identify which independently retained trace records support its intended-purpose traceability or post-market monitoring. Document the fields, relevant deployed paths, responsible provider and analysis procedure in the system-specific evidence. This fixture exercises trace transport and parentage.
