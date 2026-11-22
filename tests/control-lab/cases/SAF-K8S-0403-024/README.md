# SAF-K8S-0403-024 — Credential lifecycle metrics publication

```sh
python3 lab.py test SAF-K8S-0403-024 --docker-context desktop-linux
```

A case-owned exporter serves aggregate metrics from synthetic metadata.
Live Prometheus scrapes both the empty comparison endpoint and the populated
endpoint in Kind. The empty endpoint is healthy and exposes zero issuance
series. The populated endpoint provides four accepted issuance events over
300 seconds, or 0.01333 events per second. The mean TTL is 5,400 seconds over
three known values, with one missing value counted separately.

The case also checks one orphan across four inventory records, two approved
scope exceptions, one ignored duplicate, and one rejected unapproved event.
The series retain only case and scrape labels. All fixtures are synthetic and
both scrape targets are in-cluster routes to the owned exporter.

Workflow metadata collection across real providers and credential stores,
provenance and retention, dashboards, and periodic review need deployment
evidence.

[Prometheus exposition](https://prometheus.io/docs/instrumenting/exposition_formats/) ·
[Prometheus metric types](https://prometheus.io/docs/concepts/metric_types/)
