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

## Workload action reference

A separate namespace tests a bounded example driven by synthetic budget readings. An advisory at the limit leaves the active Job and serving Deployment in place while the actuator is disabled. An approaching reading produces an advisory and a stale reading holds the decision. A current reading at the limit triggers native Job suspension and scales the named Deployment to zero. The exact actuator identity fails authorization for an unrelated Deployment, whose Pod remains ready.

The readings model a windowed budget signal. The example reports an advisory in its receipt. Actual metering, billing delay, notification delivery, provider support, incident approvals, and the effect on spending require evidence from the deployment.

- [Google Cloud alert-only budgets](https://docs.cloud.google.com/billing/docs/how-to/budgets)
- [Google Cloud programmatic notifications](https://docs.cloud.google.com/billing/docs/how-to/budgets-programmatic-notifications)
- [AWS Budgets reporting and action controls](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html)

## Adopter verification

1. Record the approved team or namespace, billing window, currency, alert and action thresholds, cost attribution and acceptable reporting lag.
2. Reconcile actual metering and billed lines to the applicable workload, owner and device. Keep the provider estimate, delayed and adjusted lines, rate quota and actual spend identifiable in the evidence.
3. Verify delivery to the approved recipient with enough lead time for the documented response. Exercise unavailable, duplicate, out-of-order and stale inputs safely where the selected integration can produce them.
4. Use an approved synthetic workload to verify the intended action, effective authorization and a working unaffected comparator. Verify retries, overrides, recovery and which costs can continue after the action.
5. Retain reviewed policy, billing sources, timing, approvals and reconciliation. Repeat for relevant provider or workload changes and exceptions.
