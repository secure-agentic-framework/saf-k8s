# SAF-K8S-1002-006 — Sensitive metric redaction

```sh
python3 lab.py test SAF-K8S-1002-006 --docker-context desktop-linux
```

From the framework checkout, use `python3 tests/control-lab/lab.py` with the same arguments. The test runs Prometheus v3.5.0 and a synthetic metrics endpoint on Kubernetes v1.36.1 Kind.

The recording rule emits the expected cohort summaries. The three original series and their invented GPU and training labels are still queryable. The test then updates metric relabeling and reloads the existing Prometheus process. Newly scraped detail is absent, the independent safe summaries track changed values, and the original detail remains available in a historical query against the same Pod.

Production validation should cover the required ingestion paths and tenant access, safe label transformations, historical retention, and any replicated downstream stores.

[Prometheus v3.5.0 configuration](https://github.com/prometheus/prometheus/blob/v3.5.0/docs/configuration/configuration.md) · [Prometheus v3.5.0 recording rules](https://github.com/prometheus/prometheus/blob/v3.5.0/docs/configuration/recording_rules.md)
