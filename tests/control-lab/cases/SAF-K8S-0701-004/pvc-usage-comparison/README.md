# PVC usage telemetry on Kubernetes v1.36 and v1.37

Run from the SAF-K8S checkout:

```sh
python3 tests/control-lab/cases/SAF-K8S-0701-004/pvc-usage-comparison/live_compare.py \
  --docker-context desktop-linux --output /tmp/saf-pvc-usage-replay
```

Use a fresh output path. The comparison runs separate disposable clusters with pinned node and workload images. It records the native `Unused` condition before a Pod references the claim, during use, after the Pod leaves, and when a second Pod references the same claim. No feature override is applied.

In v1.36.1 the condition was absent at all four checkpoints. In v1.37.0 it alternated `NoPodsUsingPVC`, `PodUsingPVC`, `NoPodsUsingPVC`, and `PodUsingPVC`, with its timestamp advancing on each change. Both runs preserved the same bound PVC and Retain PV and returned the same inert marker from both referencing Pods. Both clusters were deleted. [v1.36.1 result](verified/v1.36.1.json), [v1.37.0 result](verified/v1.37.0.json).

Retained-data inventories can use this condition and timestamp as evidence of controller-observed Pod references on supported releases. The existing reclaim-policy test measures retention and deletion behavior. Destruction approvals and storage sanitization require separate evidence. [KEP-5541](https://www.kubernetes.dev/resources/keps/5541/), [Kubernetes v1.37 release](https://kubernetes.io/blog/2026/08/26/kubernetes-v1-37-release/#report-last-used-time-on-a-pvc).
