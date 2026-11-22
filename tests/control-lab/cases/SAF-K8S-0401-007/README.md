# SAF-K8S-0401-007 — Separate GPU-governance permissions

```sh
python3 lab.py test SAF-K8S-0401-007 --docker-context desktop-linux
```

Five local probes use their own projected ServiceAccount identities over
TLS. Before binding, every identity receives HTTP 403 for the three owned
operations. After binding, the quota role can stage an increase from two
to three synthetic units, the priority role can stage a metadata change to
one named PriorityClass, and the monitoring role can retrieve the exact
marker served by an actual HTTP fixture through the Kubernetes API Service
proxy. Each role still receives HTTP 403 for the other two actions. An
independent bounded identity exercises all three successful paths. The
API server leaves both dry-run writes unpersisted.

This fixture covers Kubernetes ResourceQuota and named PriorityClass
management and access through the Service proxy. Workload priority
assignment, direct and deployed exporter routes, hardware metrics,
identity-provider bindings and organization approvals require their own
evidence.

[Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/) ·
[Kubernetes ResourceQuota](https://v1-36.docs.kubernetes.io/docs/concepts/policy/resource-quotas/) ·
[Kubernetes Pod priority](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/pod-priority-preemption/)
