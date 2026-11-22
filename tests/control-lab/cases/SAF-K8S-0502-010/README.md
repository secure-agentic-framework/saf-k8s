# SAF-K8S-0502-010 — Service IP pool early warning

```sh
python3 lab.py test SAF-K8S-0502-010 --docker-context desktop-linux
```

A fresh Kubernetes v1.36.1 Kind cluster uses a small dedicated IPv4
ServiceCIDR. A dedicated Prometheus ServiceAccount has permission to get
the owned API server's metrics, and a live Prometheus queries its allocator
gauges over HTTPS. The test confirms Prometheus scraped the same gauges that
the API reported and that the alert initially stayed inactive.

Each case-owned ClusterIP Service has a unique matching IPAddress object.
When the measured free fraction falls below 50 percent, Prometheus fires
the warning with room still available. The allocator accepts one more
Service while the warning is active. Deleting only the case-owned Services
restores the observed baseline and clears the warning. The result retains
stable observations and writes the native samples to `allocator-samples.json`.

This proves a Service ClusterIP warning on the pinned version. CNI Pod
allocation, provider node pools, alert delivery and production capacity
planning have separate evidence.

[Kubernetes Service CIDRs](https://v1-36.docs.kubernetes.io/docs/tasks/network/reconfigure-default-service-ip-ranges/) ·
[Upstream allocator monitoring specification](https://www.kubernetes.dev/resources/keps/1880/#monitoring-requirements) ·
[Prometheus alerting rules](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/)
