# SAF-K8S-1001-033 source review

The original catalog record at revision
133a8698a45e2b335b51728bf4c62f7bda98d15f covers the onboarding of already
collected logs to a centralized platform. The case exercises the real
Fluent Bit Loki output and queries Loki through its own range API. Recording
the separate comparison stream shows the backend is active while the four
main source routes are disabled. Nonzero input counters confirm the files
were read before the route was enabled.
[Fluent Bit Loki output](https://docs.fluentbit.io/manual/data-pipeline/outputs/loki)
[Loki API](https://grafana.com/docs/loki/latest/reference/loki-http-api/)

The routed arm checks exact event IDs and the full original fields as
returned across the log line and stream labels. It checks the approved
export path on every record. The log
records are synthetic, and the test proves this one deployment's
aggregation behavior. Actual provider export and enterprise onboarding
remain operational evidence requirements.
