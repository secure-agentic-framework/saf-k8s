# SAF-K8S-0905-036 — Trigger a controller-driven workload halt

    python3 tests/control-lab/lab.py test SAF-K8S-0905-036 --docker-context desktop-linux

An in-cluster controller reads an explicit synthetic numeric metric and cutoff. With enforcement disabled, the over-threshold fixture stays active. Once enabled, the workload continues below the cutoff and halts at the cutoff. The controller records intent before scaling and enforcement after the scale update. The original halt record and zero replicas persist through controller restart and when the metric clears. A separate live service still responds.

Production telemetry authenticity, fail-safe recovery and reset procedures, additional workload types and deployment coverage require their own evidence.

- [Kubernetes 1.36 Deployment](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/deployment/)
- [Kubernetes 1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
