# SAF-K8S-0703-014 — Autoscaling replica limits

```sh
python3 lab.py test SAF-K8S-0703-014 --docker-context desktop-linux
```

Kubernetes 1.36.1 runs a Deployment whose test containers each have a 25m
CPU request and a 100m limit. Digest-pinned Metrics Server v0.9.1 measures
actual CPU usage. The adapter authenticates the local kubelet using its
temporary CA and the node DNS identity.

Under the same continuing demand, the HPA first brings the Deployment
to four Ready replicas with `maxReplicas: 4`. Lowering the ceiling to two
brings desired, observed and Ready counts to two even though utilization
still exceeds its target. The HPA reports `ScalingLimited=True` with the
reason `TooManyReplicas`.

This case covers the selected Deployment's HPA cap. Provider node-group
limits, GPU capacity, billing and notification-to-enforcement responses
require separate evidence in the deployed cloud environment.

[Kubernetes Horizontal Pod Autoscaling](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/autoscaling/horizontal-pod-autoscale/) ·
[Metrics Server v0.9.1](https://github.com/kubernetes-sigs/metrics-server/releases/tag/v0.9.1) ·
[Google Cloud budget behavior](https://cloud.google.com/billing/docs/how-to/budgets)
