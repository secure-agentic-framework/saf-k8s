# SAF-K8S-1002-002 — Distributed tracing for ML pipelines

```sh
python3 lab.py test SAF-K8S-1002-002 --docker-context desktop-linux
```

From the framework checkout, use `python3 tests/control-lab/lab.py` with the same arguments. A disposable Kubernetes v1.36.1 Kind cluster runs a digest-pinned OpenTelemetry Collector and synthetic ingestion, registry, and inference services. The workloads install the pinned OpenTelemetry SDK packages from PyPI. Each native training Job forwards W3C context as part of the fixture workflow.

The case verifies actual Collector output. Without the injected context, the training Job completes and starts its own trace. With the context, the Collector records the exact ingestion, training, registry, and inference parent IDs as one tree. A tagged synthetic error belongs to the intended inference span. A separate healthy workflow produces a complete, independent trace.

Production orchestrators, InferenceService CRD annotation propagation, instrumentation coverage, sampling, retention, backend durability, and incident response require deployment evidence.

[W3C Trace Context](https://www.w3.org/TR/trace-context/) · [OpenTelemetry Python propagation](https://opentelemetry.io/docs/languages/python/propagation/) · [OpenTelemetry Collector 0.136.0](https://github.com/open-telemetry/opentelemetry-collector-releases/releases/tag/v0.136.0)

The KServe v0.21.0 extension uses Standard mode and its generated internal
Service. It tests KServe carrying the configured W3C annotation into the predictor
Pod. The actual native Job and predictor use the Python OpenTelemetry SDK to
extract and export trace context. The same Collector observes the linked native
Job and KServe trace and an independent no-context predictor trace.
