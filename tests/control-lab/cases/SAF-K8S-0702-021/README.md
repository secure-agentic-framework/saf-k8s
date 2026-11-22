# SAF-K8S-0702-021 — Namespace quota monitoring and early warning

The case starts a disposable kind cluster with a namespaced,
ResourceQuota-only kube-state-metrics exporter and Prometheus. The alert
fires when declared accelerator use reaches 75 percent and remains there
for the test hold interval.

The test compares ResourceQuota status with the exporter’s used and hard
values in Prometheus. It observes 0 and 25 percent below the threshold,
then a firing alert at 75 percent while headroom remains. After one
synthetic declaration is deleted, it observes 25 percent and no firing
alert. The two test Pods request an unadvertised synthetic resource.
They stay Pending and consume no accelerator.

The evidence covers declared quota accounting, scraping, rule evaluation
and recovery. Deployed thresholds, physical device usage, dashboards,
notification routing, response, and billing evidence require independent
verification.

```sh
python3 lab.py test SAF-K8S-0702-021 --docker-context desktop-linux
```

From the framework checkout use `python3 tests/control-lab/lab.py` with the
same arguments.

- [Kubernetes v1.36 ResourceQuota](https://v1-36.docs.kubernetes.io/docs/concepts/policy/resource-quotas/#quota-for-extended-resources)
- [kube-state-metrics v2.20.0 quota metric](https://github.com/kubernetes/kube-state-metrics/blob/v2.20.0/docs/metrics/policy/resourcequota-metrics.md)
- [Prometheus alerting rules](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/)
