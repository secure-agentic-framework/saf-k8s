# SAF-K8S-0502-010 — Service and Pod IP pool early warning

```sh
python3 lab.py test SAF-K8S-0502-010 --docker-context desktop-linux
```

A fresh Kubernetes v1.36.1 Kind cluster has distinct small IPv4 ServiceCIDR
and PodCIDR ranges. The secondary ServiceCIDR has explicit fixture allocations
so unrelated system Services cannot affect its baseline. A dedicated Prometheus ServiceAccount can get the owned
API server's metrics over HTTPS. A local-only fixture exporter exposes the
measured remaining Pod capacity from the owned Kind node's host-local lease
files. Its samples are independently correlated with Ready Pod API addresses.

For each pool, the test verifies that Prometheus initially sees its baseline,
fires a capacity warning while addresses remain available, and keeps the
warning firing while the allocator assigns an address to one more fixture.
Deleting only owned Services or Pods restores the pool and clears the warning.
The snapshots are in `allocator-samples.json` and `pod-ipam-samples.json`.
The Docker node underlay is inventoried separately from the PodCIDR. Production
provider IP pools, other CNIs, alert delivery, and response procedures require
separate evidence.

- [Kubernetes Service CIDRs](https://v1-36.docs.kubernetes.io/docs/tasks/network/reconfigure-default-service-ip-ranges/)
- [Kubernetes Service IP allocator metrics](https://www.kubernetes.dev/resources/keps/1880/#monitoring-requirements)
- [CNI host-local IPAM](https://www.cni.dev/plugins/current/ipam/host-local/)
- [Prometheus alerting rules](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/)

## Verify an adopting implementation

Inventory every installed Service allocator, CNI Pod allocator and provider/node address pool, including configured CIDRs, per-node prefixes, reservations and expansion limits. For each allocator, identify its native remaining-capacity signals, scrape identity, threshold and runbook owner; compare warning time with observed allocation growth. In a preproduction fixture or approved provider validation, show that a new allocation succeeds while a warning is active, that the routed alert is received, and that cleanup/recovery clears the condition. Preserve provider console/API evidence for cloud and node pools, CNI version/configuration, alert delivery and escalation; do not infer these from Kind metrics.
