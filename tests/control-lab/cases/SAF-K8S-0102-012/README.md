# SAF-K8S-0102-012 — etcd health monitoring

```sh
python3 lab.py test SAF-K8S-0102-012
```

The test checks native readiness and status, and reads selected live etcd
metrics on a disposable v1.36.1 kind control-plane node. The client stays
inside the node and uses the case’s existing health-check identity.

Offline promtool runs first without the local rule file, then with
`alerts.yml`. The real passive sample supplies the healthy leader, quota
and local application inputs. Explicitly synthetic fixtures separately cover
telemetry absence, lost leadership, quota pressure, local application lag,
cross-member replication lag, two disk latency metrics and peer latency.
Every fault fixture verifies a silent pre-threshold evaluation and a later
firing evaluation. The test uses an isolated container with Docker network
mode none.

The rule thresholds are test fixtures. Production sizing, multi-member
availability, live peer observations and notification delivery remain
separate evidence. A member with no leader already signals availability
impact. Quota, latency, and progress alerts can offer earlier warning.

- [etcd v3.6 monitoring](https://etcd.io/docs/v3.6/op-guide/monitoring/)
- [etcd v3.6 maintenance and quota](https://etcd.io/docs/v3.6/op-guide/maintenance/)
- [Prometheus rule tests](https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/)
