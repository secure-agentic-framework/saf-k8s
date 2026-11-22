# SAF-K8S-0404-008 — Certificate expiry monitoring and alert delivery

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0404-008 --docker-context desktop-linux
```

The case issues two short-lived fixture leaves under a disposable CA and
serves them on separate HTTPS ports in the same Kind cluster. Blackbox
Exporter validates both endpoints with the fixture CA. Prometheus scrapes the
reported leaf expiry timestamps and compares them to the exact OpenSSL
`notAfter` values.

The same two sites are measurable before and after enabling the alert rule.
Only the certificate within the two-day threshold can fire. The local
Alertmanager webhook receiver records the route, certificate label, firing
state, severity, and summary for the notification.

OpenSSL is needed to create the private fixture files. The temporary
workspace and the Kind cluster are cleaned up by the runner. Production
certificate inventory, alert ownership, dashboards, routing integrations,
and renewal execution require separate evidence.

- [Blackbox Exporter TLS configuration](https://github.com/prometheus/blackbox_exporter/blob/v0.27.0/CONFIGURATION.md)
- [Prometheus alert rules](https://github.com/prometheus/prometheus/blob/v3.5.0/docs/configuration/alerting_rules.md)
- [Alertmanager webhook configuration](https://github.com/prometheus/alertmanager/blob/v0.28.1/docs/configuration.md)
