# SAF-K8S-1002-004 — AI-specific failure alerting

```sh
python3 lab.py test SAF-K8S-1002-004 --docker-context desktop-linux
```

From the framework checkout, use `python3 tests/control-lab/lab.py` with the same arguments. A disposable Kubernetes v1.36.1 Kind cluster runs digest-pinned Prometheus and Alertmanager. A fixture publishes synthetic telemetry for an affected cohort and a healthy cohort. Before the rules are installed, Prometheus reports the stale model sample and reports zero firing alerts or notifications.

The enabled rules detect six independent signals: rising training loss, stale model data, a nonzero XID code, low inference accuracy, high inference latency, and a stale training checkpoint. Each case checks that only the expected alert fires, the healthy cohort stays clear, and the intended local webhook receives the firing and resolved payloads. Fixture thresholds and receiver routing illustrate the test setup.

NVIDIA DCGM Exporter 4.8.4 defines `DCGM_FI_DEV_XID_ERRORS` as a gauge holding the last XID code. The fixture emits two distinct inert codes in decreasing order. Prometheus observes both values while the same state alert stays active. Production coverage depends on deployed telemetry, workload baselines, percentile calculation, actual GPU and exporter behavior, and incident delivery and response.

[Prometheus v3.5.0 alerting rules](https://github.com/prometheus/prometheus/blob/v3.5.0/docs/configuration/alerting_rules.md) · [Alertmanager v0.28.1 configuration](https://github.com/prometheus/alertmanager/blob/v0.28.1/docs/configuration.md) · [NVIDIA DCGM Exporter 4.8.4 metric definitions](https://raw.githubusercontent.com/NVIDIA/dcgm-exporter/4.8.4/etc/default-counters.csv)

## Adopter verification

1. **Validate signal sources.** For each claimed failure mode, identify the deployed exporter/API source, version, metric type, labels, scrape configuration and observed sample. For DCGM Exporter, confirm deployed version and the `DCGM_FI_DEV_XID_ERRORS` gauge definition; do not treat the last XID code as an event count. Provide representative safe hardware/provider records or approved synthetic staging input.
2. **Set workload-specific criteria.** Document training-loss baseline and window, model freshness definition, accuracy source and cohort, latency percentile calculation, checkpoint interval, and GPU-error semantics. Show threshold rationale, owners, false-positive evaluation and healthy-workload comparisons.
3. **Verify real delivery path.** Provide effective Alertmanager configuration, route matchers, receiver identity and endpoint ownership, authentication/TLS where applicable, grouping, retry/timeout, inhibition, silencing, and resolved-message behavior. Use a safe approved staging event and retain the receiving provider's timestamped delivery/acknowledgement, not only the sender's HTTP success.
4. **Verify operational ownership.** Show security-operations alerts reach the approved SOC/on-call queue and ML-operations alerts reach the correct service owner. Retain acknowledgment, triage outcome, escalation, and closure records; ensure misrouted or undelivered alerts raise a separate delivery-failure signal.
5. **Reconcile scope and revisions.** Inventory covered AI workloads and unmonitored failure modes, including any non-GPU or managed-service differences. Link the alert plan to the AI risk register and identify which signals indicate potential security incidents. Recheck current rule, exporter, Alertmanager and control fingerprints when any changes.

This is provider/operational adoption evidence. The scratch mapping plan narrows the related NIST clauses to SI-4(2) near-real-time analysis and SI-4(5) system-generated alerts, and removes unrelated crosswalk assertions such as audit-failure response (AU-5(2)), audit trails (AU-12(1)), audit content (AU-3(1)), org-generated external-source alerts (SI-4(12)), audit repository correlation, enterprise situational awareness, advisory consumption and supply-chain artifact traceability. Those are different mechanisms.

The SI-4(2) and SI-4(5) relations are conditional on selected monitored system events, applicable indicators and routing to assigned recipients.

[NIST SP 800-53 Revision 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
