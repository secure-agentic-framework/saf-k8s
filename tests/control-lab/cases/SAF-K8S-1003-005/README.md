# Verify selected Kubernetes alert rules and their runbook labels

    python3 tests/control-lab/lab.py test SAF-K8S-1003-005 --docker-context desktop-linux

The case runs the reviewed Prometheus rules against fixed synthetic event
fixtures. It compares the expected matches and the out-of-scope records,
then checks the enrolled rule digest and the corresponding runbook labels.

A pinned Prometheus server scrapes fixed metrics from an owned fixture
endpoint in Kind. An independent read-only observer checks the alerts API
for the two expected firing alerts with the exact reviewed labels and
checks for additional alerts. A pinned Alertmanager routes each firing alert to its assigned case-owned receipt path. The independent observer checks the exact rule, marker, technique, runbook and route for both alerts. The fixture mounts the reviewed rule bytes
and records the corresponding digest.

For a deployment, confirm which real audit and runtime sources feed each
prioritized detection, how their observations become metrics, and which
workflow receives the resulting alert. Verify authorized benign exercises,
each delivery route, analyst access, false-positive handling, retention
and review after rule or source changes. This case uses synthetic metrics.

[Alertmanager v0.28.1 configuration](https://github.com/prometheus/alertmanager/blob/v0.28.1/docs/configuration.md)
