# SAF-K8S-0703-009 — Requested GPU spending rate admission

```sh
python3 lab.py test SAF-K8S-0703-009 --docker-context desktop-linux
```

Kueue v0.20.6 runs on a disposable Kubernetes v1.36.1 cluster.
The case verifies the release manifest digest and pins the controller
image digest. One queue accounts for a synthetic requested rate
resource. An integer unit represents a fictional USD per hour.

With a permissive six-unit limit, the controller reserves requests of
three, two and one unit. After the one-unit request is removed and the
limit becomes five, the same request waits for quota. Releasing the
two-unit reservation lets the waiting request reserve one unit. The
case checks actual quota status and resource usage. Raw Workloads
exercise admission without creating fixture Pods.

A rate cap does not accumulate spending over a budget period.
Production metering, provider pricing, billing reconciliation,
tenant authority, alerts and repayment or shutdown actions require
separate evidence.

- [Kueue v0.20.6 release](https://github.com/kubernetes-sigs/kueue/releases/tag/v0.20.6)
- [Kueue v0.20 ClusterQueue](https://kueue.sigs.k8s.io/v0.20/docs/concepts/cluster_queue/)
- [Kueue v0.20 Workload status](https://kueue.sigs.k8s.io/v0.20/docs/concepts/workload/)
