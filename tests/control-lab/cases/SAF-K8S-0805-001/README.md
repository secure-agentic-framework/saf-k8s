# SAF-K8S-0805-001 Accelerator telemetry coverage and alert evaluation

Kind runs a pinned Prometheus image and a small HTTP fixture with preset normal, high and missing series. Observe all three successful scrapes first with no rules, then observe distinct threshold and missing-series alerts firing while the normal sample remains available and quiet. The test uses no accelerator or exporter hardware integration. Actual telemetry coverage, hardware attribution and incident triage require separate evidence.

## Additive local alert-route check

The scratch supplement preserves the three published scrape and rule checks and
adds one live routing check. It reuses the existing owned synthetic exporter,
starts a second pinned Prometheus and the pinned Alertmanager v0.28.1 already
used by other published SAF-K8S cases, and routes only the fixed high and
missing fixture alerts to a case-owned in-cluster receiver. The receiver stores
only the route name, firing state and selected fixture alert labels. The check
requires the high and missing identities, requires that no normal-target
notification appears during its bounded observation, and rejects unexpected
alert identities. It does not claim exactly-once notification.

The local receiver rejects bodies over 8 KiB, groups over two alerts, more than
eight stored messages, and selected label values longer than 160 characters.
The scratch-only `route_logic_test.py` checks missing, unexpected, normal-target
and unreadable-read counterfactuals; it makes no cluster calls and adds no
receipt checks.

This observes local Prometheus-to-Alertmanager-to-receiver configuration for
synthetic samples. It does not test an actual accelerator exporter, device
coverage, workload attribution, durable retention, or delivery to an approved
external responder. Expected total: four checks, with the original three
unchanged. The additive raw artifact is `alert-route-delivery.raw.json`.
