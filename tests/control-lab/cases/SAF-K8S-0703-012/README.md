# SAF-K8S-0703-012 — Dedicated node pools for sensitive AI workloads

```bash
python3 lab.py test SAF-K8S-0703-012 --docker-context desktop-linux
```

A fresh three-node kind cluster has separate AI and general workers. The same
AI-affine workload schedules before the dedicated-pool taint and remains pending
with the exact untolerated taint after activation. The existing placement is
preserved by NoSchedule. An AI Pod with exact product affinity and the matching
toleration schedules to the AI worker, while an ordinary Pod schedules to the
general worker.

Separately, admission policy rejects the opted-in incomplete declaration admitted
before policy, and admits one with the required selector terms and toleration.
Who may set the qualifying labels and tolerations, the actual production node
pool, accelerator capacity and driver configuration require deployment evidence.

[Kubernetes taints and tolerations](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/) ·
[Kubernetes node affinity](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/) ·
[Kubernetes admission policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
