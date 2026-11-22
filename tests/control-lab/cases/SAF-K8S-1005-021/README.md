# SAF-K8S-1005-021 — Targeted Kubernetes containment

Run from the control lab with `python3 lab.py test SAF-K8S-1005-021 --docker-context desktop-linux`. The runner creates and deletes a two-node Kind cluster pinned to Kubernetes v1.36.1.

The maintenance Deployment and independent HTTP fixtures carry only case-owned data. An initial temporary scheduling taint makes the maintenance Pod land on the worker without changing the Deployment template. After the taint is removed, a drain restricted to the fixture Pod selector cordons that worker and evicts the maintenance Pod. Its replacement becomes Ready on the control-plane node under the same Deployment generation.

Fixed Pod-to-Pod HTTP requests read distinct markers in both directions before and after rescheduling. The same requests are blocked after a namespace-scoped default-deny NetworkPolicy goes into effect while the isolated Pod remains Ready. The final scale operation removes the maintenance Pod and retains its Deployment. A separate HTTP client confirms the independent workload remains reachable at the observed checkpoints. The independent Pod UID and restart count are checked after containment.

The raw receipt retains the relevant names, API objects, and drain output. The structured report records deterministic outcomes across the two disposable clusters. This covers the bundled Kind network implementation and the observed fixture requests. It leaves production disruption budgets, other CNI and tenant topologies, organizational authorization and incident procedures, rollout recovery, and real AI workload behavior for independent review.

- [Safely drain a node](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/safely-drain-node/)
- [Kubernetes Network Policies](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Scale a Deployment](https://v1-36.docs.kubernetes.io/docs/tasks/run-application/scale-deployment/)
