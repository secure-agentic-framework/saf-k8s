# SAF-K8S-1002-004 — AI-specific failure alerting

```sh
python3 lab.py test SAF-K8S-1002-004 --docker-context desktop-linux
```

From the framework checkout, use `python3 tests/control-lab/lab.py` with the same arguments. A disposable Kubernetes v1.36.1 Kind cluster runs digest-pinned Prometheus and Alertmanager. A fixture publishes synthetic telemetry for an affected cohort and a healthy cohort. Before the rules are installed, Prometheus reports the stale model sample and reports zero firing alerts or notifications.

The enabled rules detect six independent signals: rising training loss, stale model data, a nonzero XID code, low inference accuracy, high inference latency, and a stale training checkpoint. Each case checks that only the expected alert fires, the healthy cohort stays clear, and the intended local webhook receives the firing and resolved payloads. Fixture thresholds and receiver routing illustrate the test setup.

NVIDIA DCGM Exporter 4.8.4 defines `DCGM_FI_DEV_XID_ERRORS` as a gauge holding the last XID code. The fixture publishes that gauge with an inert code. Production coverage depends on deployed telemetry, workload baselines, percentile calculation, actual GPU and exporter behavior, and incident delivery and response.

[Prometheus v3.5.0 alerting rules](https://github.com/prometheus/prometheus/blob/v3.5.0/docs/configuration/alerting_rules.md) · [Alertmanager v0.28.1 configuration](https://github.com/prometheus/alertmanager/blob/v0.28.1/docs/configuration.md) · [NVIDIA DCGM Exporter 4.8.4 metric definitions](https://raw.githubusercontent.com/NVIDIA/dcgm-exporter/4.8.4/etc/default-counters.csv)
