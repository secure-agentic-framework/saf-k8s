# SAF-K8S-1007-011 — Cluster maintenance sequence and rollback decision

Run with the existing control-lab runner:

```sh
python3 lab.py test SAF-K8S-1007-011 --docker-context desktop-linux
```

The runner provisions its disposable, default-profile Kind cluster from the digest-pinned
`kindest/node:v1.36.1` image. No custom Kind profile is required. The case captures the API
server and kubectl versions, the controller-manager and scheduler image versions, each
Node's kubelet version and readiness, and kube-proxy image versions from Kubernetes API
objects. The raw snapshots contain only version and cluster metadata for this fresh,
case-owned cluster; the case creates no Secret objects and does not collect credentials.

The case derives a one-minor target from the observed API server version. It first rejects
an intentionally invalid plan that places kubelet before the control plane and models a
newer kubelet while the API server is still old. The green plan then checks every synthetic
intermediate component state against the official Kubernetes v1.36 version-skew rules:
API server first, control-plane components next, drain-before-kubelet maintenance, then
optional kube-proxy update and post-upgrade validation. Each run writes
`component-versions.raw.json`, `red-maintenance-plan.raw.json`, and
`green-maintenance-plan.raw.json` to the runner's evidence directory.
The modeled candidate uses the next minor's `.0` version string to exercise the minor
boundary; it is not a release recommendation. Kubernetes recommends choosing the latest
patch of the current and target minor before a real upgrade.

This is a **plan and policy simulation**, not a Kubernetes upgrade. The default Kind
cluster has a single control-plane node; the case does not drain it or claim an observed
worker-node maintenance. It does not install a second Kubernetes version or mutate
control-plane, kubelet, or kube-proxy binaries. The version-skew checks are based on live
versions observed for the cluster under test, but the proposed next-minor versions and
intermediate states are modeled fixture data.

For a separate rollback exercise, a single-replica, tokenless Deployment runs the official
Python mock image pinned by digest. Its only process sleeps; it does not initiate network
I/O or read mounted input. The candidate Pod is observed Ready, while its failed-health
signal is an explicit synthetic fixture value rather than measured service health. The case
changes a reserved stable marker to a candidate marker, consumes a
fixture-only failed health outcome, records a mock rollback decision referencing the
exact stable fixture URN, and calls `kubectl rollout undo` on this Deployment only. The
positive check verifies the new API-observed Deployment revision, generation, readiness,
and release markers. `mock-rollback-decision.raw.json` and
`mock-workload-rollback.raw.json` preserve those observations. This is workload revision
rollback inside the fixture; it is not Kubernetes control-plane/node downgrade or
disaster-recovery evidence, and this case makes no claim about the availability or support
of a true Kubernetes downgrade path.

## Coverage and limits

The case provides independently recorded red, green, and positive outcomes for (1) an
out-of-order / incompatible version plan, (2) an ordered one-minor synthetic plan against
the observed component versions and upstream skew policy, and (3) a fixture-only mock
workload rollback. It does not establish change approval, actual component upgrades,
production maintenance sequencing, multi-control-plane behavior, worker draining, or
successful recovery from a Kubernetes version downgrade. Do not infer a true Kubernetes
downgrade or recovery capability from Deployment rollout undo.

Add-on compatibility is not established. Real clusters must separately inventory and
validate their CNI, CoreDNS, CSI/storage drivers, device plugins and GPU operators,
admission webhooks, observability agents, and managed-service components against their
own compatibility and upgrade guidance. Production upgrade windows, backups, etcd
recovery, application health, availability impact, authorization, and provider coordination
also require separate evidence. No production environment or external target is contacted.

## Official primary sources

- [Kubernetes v1.36 Version Skew Policy](https://v1-36.docs.kubernetes.io/releases/version-skew-policy/) — component skew limits and supported upgrade order for a 1.36 to 1.37 transition.
- [Kubernetes: Upgrading kubeadm clusters](https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade/) — kubeadm control-plane procedure and upgrade checks.
- [Kubernetes: Upgrading Linux nodes](https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/upgrading-linux-nodes/) — control-plane-before-worker guidance, draining, kubelet update, and uncordon sequence.
- [Kind v0.32.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0) — publishes the pinned v1.36.1 node image digest used by the lab runner.
- [Docker Official Images: Python](https://github.com/docker-library/official-images/blob/master/library/python) — official-image metadata source for the digest-pinned mock runtime reference.
