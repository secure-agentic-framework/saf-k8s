# SAF-K8S-0905-034 — Keep candidate and stable versions isolated

    python3 tests/control-lab/lab.py test SAF-K8S-0905-034 --docker-context desktop-linux

Two inert model versions run behind separate Services and namespaces. A fixture router reads a ConfigMap protected by Kubernetes RBAC and routes a fixed, evenly spaced cohort. The designated approver can set the split, and the candidate identity cannot change it. The native NetworkPolicy denies the same direct candidate-to-stable connection that succeeded before policy activation. The approved 80/20 split keeps serving, and stable remains reachable after withdrawing the candidate.

Verify production routing, service mesh configuration, workload resources and GPU isolation separately.

- [Kubernetes 1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes 1.36 NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)
