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

## Scratch review addition: expected-peer telemetry presence

The reviewed scratch variant adds `EtcdPeerTelemetryUnavailable`, gated by an
`etcd_expected_peer_count` inventory series. Its three appended `promtool`
scenarios are explicitly synthetic: a singleton with zero expected peers and
no peer histogram stays quiet; a target with expected peers, `up=1`, and no
peer histogram fires a distinct missing-telemetry alert after its hold; and a
target with expected peers plus peer histogram samples does not fire that
missing-telemetry alert. The expected-peer series is not an etcd-native metric
and no live peer samples are claimed by this fixture. Production use requires
an independently maintained expected topology/inventory input and tests that
its values match the cluster membership. The existing passive member checks
and receipt scope remain unchanged.

Adopter evidence should show the monitored member inventory, expected peer
count for each member, actual scrape target identity and `up` state, presence
of each applicable peer histogram series by `To`, rule evaluation, and the
notification route's delivery receipt. For single-member deployments, document
that no peer RTT series is expected. For managed control planes, retain the
provider's available telemetry inventory and explicitly mark unavailable
metrics rather than treating a synthetic rule fixture as observed data.

The sample compares the number of distinct nonempty `To` labels with the
expected count while the scrape succeeds. One observed peer out of two expected
peers still alerts. An expected count is insufficient to identify a substituted
peer, so reviewers also reconcile observed peer identities to the exact approved
member inventory. Verify that exporter relabeling preserves these identities.
