# SAF-K8S-0102-021 loopback exporter bridge (scratch copy)

This is a scratch copy of the published `case.py` and `alerts.yml`; see
`README-published.md` for the prior scope and source references. It preserves the
current pinned Kind certificate inspection, Prometheus `promtool` image and
synthetic threshold/missing-data comparisons.

The addition starts a tiny reference HTTP exporter bound only to `127.0.0.1`
and an ephemeral port. It exposes exactly the three certificate expiry samples
already measured from the case-owned Kind node. A strict built-in Python parser
reads at most 4096 bytes, requires exact cluster/member/role labels, one series
per expected tuple, a fresh timestamp, finite nonnegative seconds, and values
within five seconds of the public certificate inventory. Parser-negative
fixtures check missing role/member, extra role, duplicate tuple, unexpected
member and stale sample rejection. One synchronous `HTTPServer` thread serves
the single local request; the local client socket timeout is two seconds and server join is
bounded to three seconds. No package is downloaded or installed.

The parsed healthy samples replace the prior helper-constructed healthy input
to the existing promtool rule fixture. Synthetic before-boundary, exact
boundary, expired, missing-series and no-rule comparisons remain as the
controlled rule-semantics oracle. The loopback exporter is a **reference
fixture**, not an adopter exporter. The fixture's source leaf data is the local
Kind node only. It does not fetch deployed metadata, bind a production or
adopter endpoint, infer an exporter mapping, or prove notification delivery.

## Adopter endpoint and notification acceptance

To close deployment evidence in `saf-lab-0102-021.1`, apply the same checks to
the adopter-selected exporter's actual, approved scrape endpoint and exact
version/config revision. Record the expected cluster/member inventory and
the documented source metric-to-role mapping. Require exactly one fresh sample
for every `(cluster, member, certificate role)`; fail on missing, duplicate,
unexpected, stale, nonfinite or mismatched series. Correlate each sample with
the corresponding public certificate expiry using an agreed bounded timestamp
and quantization tolerance. Retain only sanitized predicates and versioned
provenance; do not retain keys, credentials, or unrelated raw exporter output.

Feed those verified real scrape samples to the same pinned rule evaluation for
the healthy observation. Keep controlled synthetic threshold cases for
before/at/after the lead boundary and missing data. Separately prove the real
alert route with an approved test receiver and a received notification,
including owner, escalation, realistic remediation lead time and evidence of
completion. A local rule evaluation is not notification-path proof.

## Bounded dependencies

- Kubernetes node: `kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`.
- Prometheus rule evaluator: `prom/prometheus:v3.5.0@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996`.
- Reference exporter/parser: Python standard library only (`http.server`, `threading`, `http.client`, `re`, `math`). No additional images, packages, services, or dependencies.
- Adopter mode: adopter must pin and report its own exporter version/digest, scrape config revision and expected member inventory; no generic exporter is assumed.

## Inert notification route

The case submits two synthetic alert events to a disposable Alertmanager.
Its route delivers only the event matching the approved fixture cluster,
expiry rule, severity and certificate role to a local inert receiver.
The receiver retains the matching event in memory. The other event leaves
the receiver count unchanged. The separate Promtool checks prove the
rule decisions for the observed healthy inventory and modeled faults.

For adoption, verify the real exporter-to-rule link, actual rule-to-
Alertmanager delivery, and acknowledgement at the approved receiver.
Record the route, timing, owner, certificate scope and escalation evidence.
