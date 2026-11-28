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

The scratch candidate also adds `visibility_failure.py`, an isolated synthetic
route proof. It first records the `vanished` scrape job at `up=1` with its
metric, then removes only that job from the Prometheus scrape configuration and
reloads it. The proof requires a separate failed scrape to retain an
`up{job="failed"}` sample of zero, the removed target to have no `up` series
while `absent(up{job="vanished"})` returns one, and a healthy peer source to
retain `up=1` plus its metric. It waits for both firing alerts and their exact
case-local webhook receipts before recording the check. The target loss is
induced through a synthetic config reload; this does not prove GPU telemetry
or production service-discovery behavior.

A separate visibility route replays two collection failures. A synthetic HTTP
503 produces a failed scrape with `up=0` and an absent device metric. Removing
a previously observed job leaves no fresh `up` series in a six-second query
lookback and exercises `absent_over_time(up[6s])`. The receipt compares the
five-minute instant query separately.
A separate healthy scrape path on the same fixture exporter reports a
measured zero throughout, and each failure creates its own exact case-local
Alertmanager delivery. The runner waits for the new
projected config before reloading Prometheus and retains
`source-visibility-route.raw.json`. This check uses an HTTP fixture on Kind.
The A100 device and its visibility loss require a separate hardware run.

[Prometheus lookback and staleness](https://prometheus.io/docs/prometheus/latest/querying/basics/#staleness).
