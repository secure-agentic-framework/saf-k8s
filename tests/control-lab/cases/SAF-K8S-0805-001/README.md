# SAF-K8S-0805-001 accelerator telemetry and alert delivery

Run from the framework checkout.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0805-001 --docker-context desktop-linux
```

The case uses pinned Prometheus and Alertmanager images and a local web
receiver. Its fixed normal, high, and missing series exercise scraping,
threshold detection, missing-signal alerts, and delivery.

The T4 replay uses both hardware runs preserved in the public
`SAF-K8S-1002-003` reference summary. The summary and its four source
receipt digests are pinned. Each source receipt digest was compared with
the retained bytes during review. The case projects framebuffer readings,
capture intervals, sample skew, receipt digests, and pseudonymous workload
references.

Both runs recorded 0 MiB idle and 232 MiB after a deliberate framebuffer
allocation in a known-good workload. The replay labels all samples as
historical. Prometheus evaluates a 100 MiB fixture threshold and
Alertmanager delivers only the two allocated capture identities with their
workload references. Both idle samples remain visible and quiet. Prometheus
timestamps describe the replay. Live freshness, collection coverage, and
incident determination require further evidence.

The runner records five checks. The historical route artifact is
`t4-historical-alert-route.raw.json`. [T4 reference summary](https://github.com/secure-agentic-framework/saf-k8s/blob/23a8b7a4be1fec186b4138fc30e12ab0964e33b9/tests/control-lab/cases/SAF-K8S-1002-003/t4-reference/reference-result.json)

The [live A100 telemetry reference](../SAF-K8S-1002-003/a100-reference/README.md)
records a real allocation and a fresh, workload-attributed DCGM threshold.
