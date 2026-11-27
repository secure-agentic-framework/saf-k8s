# SAF-K8S-1007-007 — Cluster service protection

The case retains the 11 admission, priority and health checks and adds three checks with a TLS-verified Metrics Server. Run `python3 tests/control-lab/lab.py test SAF-K8S-1007-007 --docker-context desktop-linux` from the framework checkout. This normal test command builds a temporary Kind profile for the owned cluster.

## Added observations

- Reuse the 1002-005 Metrics Server v0.8.1 manifest digest and image digest. The case creates temporary kubelet and APIService certificates, configures the single owned Kind control-plane kubelet to serve the fixture certificate, and verifies the APIService CA bundle and service identity. TLS verification remains enabled for kubelet and aggregation.
- Read the actual `metrics.k8s.io/v1beta1` PodMetrics object for `saf-test/saf-1007-007-shared-health` before and after the existing quota probes. Each sample must have CPU and memory usage, be no older than 90 seconds, and be bracketed by Pod API reads with the same UID as the original fixture Pod. Raw metrics responses and resource quantities are not retained.
- Read at most the last 100 lines from that Pod's `mock-workload` container before and after. The check stores only whether fixed `/healthz` HTTP 200 entries were present and whether their count increased. It does not retain log text.

The three added checks are one trusted APIService setup check from the reused helper, one grouped before/after native PodMetrics check, and one grouped before/after read-only log check. Total expected count: 14, including the original 11.

## Bounds and limits

The existing fixture requests 5m CPU and 8Mi memory and continues to serve its fixed marker. No workload load is generated. Metrics Server installation and PodMetrics polling are bounded by the helper's command timeouts and a 100-second deadline for each sample; log reads are capped at 100 lines and 15 seconds. All additional resources are in the case-owned Kind cluster, which the normal runner deletes on completion. The dynamic Kind profile and generated private material are under the runner's temporary directory.

This demonstrates a fresh resource-metrics read and native container-log read for one synthetic Pod in this Kind profile. It does not establish production log forwarding, durable collection, monitoring alert behavior, metrics quality under workload, scheduling under contention, or real cluster capacity protection. The existing 11 checks and their claim limits remain unchanged.

## Dependencies

- Existing lab runner's normal `run` path and local Kind v1.36.1 node image.
- OpenSSL, curl, kubectl, and access to the pinned official Metrics Server v0.8.1 release manifest and digest-pinned image, as in SAF-K8S-1002-005.
- No new Python package or real credential is introduced.

## Bounded coexistence addition

After the original 14 checks, the supplement starts one separate CPU-only HTTP
fixture Pod in `saf-test` with 5m CPU and 8Mi memory requests. The existing
shared-health Pod uses the same requests; both remain well below the existing
20m/32Mi requests quota. A distinct Service selects only the new Pod. The
case checks both Pods remain Ready, each Service has the exact Pod endpoint and
returns its own fixed benign marker, then reads two fresh `PodMetrics` samples
for the companion Pod while confirming the original Pod UID remains present.
The actual CPU and memory quantity strings and metric timestamps are retained
in `bounded-coexistence-observations.json`. The companion is deleted afterward
and the quota must return to the original 5m/8Mi usage. Expected total: 15
checks.

This is one low-resource coexistence observation in Kind, not a load or
contention test. It does not demonstrate behavior under large-scale training,
control-plane exhaustion, production CoreDNS latency, metrics scraping under
pressure, or production log forwarding.

## Bounds and limits

The existing fixture requests 5m CPU and 8Mi memory and continues to serve its fixed marker. No workload load is generated. Metrics Server installation and PodMetrics polling are bounded by the helper's command timeouts and a 100-second deadline for each sample; log reads are capped at 100 lines and 15 seconds. All additional resources are in the case-owned Kind cluster, which the normal runner deletes on completion. The dynamic Kind profile and generated private material are under the runner's temporary directory.

This demonstrates a fresh resource-metrics read and native container-log read for one synthetic Pod in this Kind profile. It does not establish production log forwarding, durable collection, monitoring alert behavior, metrics quality under workload, scheduling under contention, or real cluster capacity protection. The existing 11 checks and their claim limits remain unchanged.

## Dependencies

- Existing lab runner's normal `run` path and local Kind v1.36.1 node image.
- OpenSSL, curl, kubectl, and access to the pinned official Metrics Server v0.8.1 release manifest and digest-pinned image, as in SAF-K8S-1002-005.
- No new Python package or real credential is introduced.

## Additive scheduler contention comparison

The published 15 checks remain in place. The additive fixture creates a case-owned
Kind worker labelled `saf-lab.example/scheduler-target=owned`. The disposable
worker is tainted against unrelated workload placement. Its worker-only kubelet
configuration drop-in derives `systemReserved.cpu` from Docker host CPU count
to target 1000m allocatable. The case checks the observed Node allocatable value
before creating workloads and stops as setup failure if the target differs. The
pinned Metrics Server kubelet certificate covers both node names so existing
PodMetrics checks retain TLS verification. The fixture Metrics Server tolerates
the control-plane taint and is placed on that node. The control-plane and worker
kubelets use only short-lived fixture certificates from the runner's temporary
directory.

The original health/companion fixtures tolerate the ordinary control-plane taint
and remain on the control-plane node. The scheduler fixture samples existing
worker Pod CPU requests, confirms existing worker Pods are not eligible victims,
then chooses a bounded idle holder request that leaves a fixed margin and adds a 250m service request
that cannot fit alongside the holder. It uses a separate case-owned namespace
with a 1500m/128Mi/4-Pod ResourceQuota. Each container only sleeps; CPU and
memory requests exercise scheduler accounting, not actual load or cgroup
isolation.

The two policy phases are sequential on the same worker and use the same
requests. First, a high-priority `preemptionPolicy: Never` Pod must remain
Pending with the scheduler's `Insufficient cpu` condition while the exact
low-priority holder UID remains Ready. After the holder is explicitly deleted
with a UID precondition, that same non-preempting Pod must become Ready. The
fixture then retires it by UID, recreates the holder, and submits a higher
priority Pod with `PreemptLowerPriority`. It requires a `Preempted` event from
the default scheduler on the exact victim UID naming the exact preemptor, the
victim's disappearance, the preemptor's Ready state, and no other initial worker
Pod UID retirement. The event, full API objects, worker inventory and dynamic
UIDs are retained only in `scheduler-contention-raw.json`; check observations
are normalized booleans. The final check verifies namespace and PriorityClass
cleanup. Expected total: 22 checks.

This demonstrates bounded scheduler request accounting, non-preemption, and one
same-node victim/preemptor transition in a disposable Kind cluster. The tested
preemption victim is a standalone Ready Pod without volumes or a custom Permit
plugin; this does not cover the v1.36 preemption behavior for Pods still in
PreBind. It does not
measure CPU saturation, large-scale training behavior, built-in critical
component protection, production capacity, service latency, logging pipelines,
or production availability. Actual deployed cluster sizing and service health
remain adopter evidence.


## Verify capacity and placement

ResourceQuota governs namespace admission for the configured accounting fields.
Check its `status.hard` and `status.used` values together with the effective
service and training Pod requests, Node allocatable resources, and the eligible
placement topology. Quota totals can exceed available capacity and do not
reserve resources on a Node. Priority influences ordering and eligible preemption.
Confirm the applicable priority class, independent capacity or isolation, and
service health under a representative approved workload. Keep the topology,
measured headroom, DNS, metrics, and log delivery observations with the review.

[Kubernetes ResourceQuota semantics](https://v1-36.docs.kubernetes.io/docs/concepts/policy/resource-quotas/#how-kubernetes-resourcequotas-work)
[Kubernetes Pod priority](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/pod-priority-preemption/)
