# SAF-K8S-1002-003 — AI workload telemetry integration

```sh
python3 lab.py test SAF-K8S-1002-003 --docker-context desktop-linux
```

From the framework checkout, use `python3 tests/control-lab/lab.py` with the same arguments. The test uses the checksum-pinned Prometheus Operator v0.85.0 release bundle and digest-pinned images on a fresh Kubernetes v1.36.1 Kind cluster.

The original four checks remain: the synthetic CPU training service runs three epochs; the synthetic inference service measures a classification pass and reports latency and its seven-of-eight quality marker; both have no samples before enrollment; and the ServiceMonitor/PodMonitor, unselected comparison, and discovery RBAC are checked.

An additive native producer check uses the published `SAF-K8S-0903-004` companion. It validates SHA-256 for `llama_runtime.py`, `Dockerfile.llama`, and `llama_client.py`, runs the exact b9519 CPU image and checksum-pinned tiny Stories model, enables `--metrics`, and enrolls the server with a ServiceMonitor. It observes `llamacpp:tokens_predicted_total` after target `up=1`, records a pre-completion baseline, sends the companion's fixed completion, and requires the Prometheus counter increase to equal the client-reported four generated tokens. It demonstrates one CPU inference producer-to-scrape path in this disposable cluster. GPU/DCGM telemetry, production identity attribution, and durable monitoring are outside the evidence.

An additive CPU training witness imports the exact SHA-256 checked `gloo_runtime.py`, Dockerfile, and architecture wheel locks from the published `SAF-K8S-0901-002` companion. The pinned PyTorch 2.15.0+cpu image runs a fixed, four-row synthetic linear regression with three real `torch.nn.MSELoss`/`torch.optim.SGD` updates. The app-owned Prometheus text endpoint is zero before the bounded `/train` request; after training, Prometheus must scrape the exact optimizer-step counter and a loss gauge equal to the independently read training receipt. This demonstrates a real CPU PyTorch training step-to-scrape path with instrumentation derived from framework measurements. It does not claim PyTorch supplies a native Prometheus exporter, validate provider-deployed training signals, use real data, or establish GPU/DCGM telemetry.

The server Pod Ready wait is 190 seconds, with a 200-second command ceiling. The pinned companion startup probe allows approximately 180 seconds (`failureThreshold: 90`, `periodSeconds: 2`), so this wait no longer ends before that probe allowance. Target discovery (100 seconds), client readiness (60 seconds), completion command (75 seconds), and post-request metric observation (90 seconds) retain their original bounds.

The llama dependency is `HERE.parent / "SAF-K8S-0903-004"`, and the PyTorch builder dependency is the published `SAF-K8S-0901-002` sibling under `tests/control-lab/cases`. A normal source-tree run resolves both directly. The control-lab approval loader copies only the selected case into a temporary directory; when loading this case through that path, set `SAF_CONTROL_CASES_ROOT` to the original published `tests/control-lab/cases` directory. Each helper validates required companion hashes before use. The PyTorch builder and wheel locks are not duplicated into this case.

Raw outputs are written to `llama-metrics-client.raw.log` (bounded actual client receipt) and `llama-native-prometheus.raw.json` (baseline, target-up labels, completion response, after sample, and observed delta). The existing `telemetry-observed.json` remains for the original four checks.

The scraper service account can list EndpointSlices in the fixture namespace. Kubernetes denies the same discovery request in another namespace and denies Secret reads. Check the retained observations for raw Prometheus query results, target states and discovery decisions.

The PyTorch addition contributes two checks after the seven existing enrollment,
native-inference, and monitor-retirement checks: a zero optimizer-step baseline
before the explicit training request, then a positive three-step counter delta
and scraped loss matching the independently read fixed training receipt. Raw
files are `pytorch-training-baseline.raw.json` and
`pytorch-training-prometheus.raw.json`. The extra PodMonitor is created only
after the original monitor-retirement assertions, so the earlier pool set and
removal checks retain their exact scope.

Provider-deployed training and serving framework instrumentation, GPU nodes and taints, exporter field availability, production identity attribution, and real device metrics require separate deployment evidence.

[Prometheus Operator v0.85.0](https://github.com/prometheus-operator/prometheus-operator/releases/tag/v0.85.0) · [Prometheus Operator troubleshooting](https://prometheus-operator.dev/docs/platform/troubleshooting/) · [NVIDIA DCGM Exporter](https://docs.nvidia.com/datacenter/cloud-native/gpu-telemetry/latest/dcgm-exporter.html)

For adoption, record the actual vendor, hardware, driver, exporter version and metric field support for accelerator signals. Compare the exporter output with independently scraped, workload-attributed samples for the deployed nodes. For training and inference, record each real source, signal semantics, runtime version, identity labels, authorized scrape selectors and controlled coverage limits. The fixture's fixed quality, training and inference values exercise collection.

- [PyTorch 2.15 SGD optimizer](https://docs.pytorch.org/docs/2.15/generated/torch.optim.SGD.html) and [MSELoss](https://docs.pytorch.org/docs/2.15/generated/torch.nn.modules.loss.MSELoss.html) — the case's actual backward/optimizer update and measured loss.

- [NVIDIA DCGM Exporter installation and compatibility](https://docs.nvidia.com/datacenter/dcgm/latest/installation/install-dcgm-exporter.html)
- [NVIDIA DCGM Exporter metric support](https://docs.nvidia.com/datacenter/dcgm/latest/reference/dcgm-exporter-metrics.html)

The native counter proof requires a fresh zero-valued scrape and a later scrape
from the same labeled series, with the two actual sample timestamps and values
retained in raw evidence. The new monitor has a separate bounded convergence wait.

## Monitor removal and bounded query freshness

The case removes the training ServiceMonitor and inference PodMonitor in order.
Before each deletion it confirms that the expected targets and samples are
visible. After each deletion it requires the removed pool to disappear and
its synthetic series to be absent under an explicit 30-second per-query
lookback. The remaining inference signals are available after the first
removal, and the independently monitored llama.cpp counter remains at four
through both removals.

Each removal has a 240-second convergence window. The receipt retains the
actual target status, short-lookback query, a default-lookback comparison,
five-minute range data, and bounded reload diagnostics. This demonstrates
retirement for the selected active target and query window. Default-lookback
expiry, stored history deletion, and deployed retention have separate evidence
requirements.

- [Prometheus v3.5.0 query request options](https://github.com/prometheus/prometheus/blob/v3.5.0/web/api/v1/api.go)
- [Prometheus v3.5.0 staleness](https://github.com/prometheus/prometheus/blob/v3.5.0/docs/querying/basics.md#staleness)
