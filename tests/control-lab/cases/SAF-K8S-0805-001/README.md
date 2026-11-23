# SAF-K8S-0805-001 Accelerator telemetry coverage and alert evaluation

Kind runs a pinned Prometheus image and a small HTTP fixture with preset normal, high and missing series. Observe all three successful scrapes first with no rules, then observe distinct threshold and missing-series alerts firing while the normal sample remains available and quiet. The test uses no accelerator or exporter hardware integration. Routed notifications, actual telemetry coverage, hardware attribution and incident triage require separate evidence.
