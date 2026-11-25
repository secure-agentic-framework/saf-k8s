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

## Pod priority assignment

A separate namespaced admission check acts on server-side dry-run Pod
requests. Before admission policy, two synthetic identities with Pod
create access can both select the governed class. The scoped policy
allows selection by the approved identity and refuses an unapproved
selection. Ordinary and default priorities remain available. The case
also checks that the binding targets the intended fixture namespace.

## Adopter verification

1. Inventory effective identity-provider groups and Kubernetes bindings.
   Record approved assignments for quota, priority, and telemetry duties.
2. Match authorized quota administration to the actual extended resource
   keys or claim quotas and review its audit trail.
3. Evaluate PriorityClass administration and Pod class selection
   separately. Rehearse denied and allowed requests using the approved
   mechanism and an authorized test identity.
4. Check service-proxy grants and the actual direct exporter path, including
   separate routing and scrape authorization where applicable.
5. Retain the owner, rationale, compensating controls, independent
   approval, expiry, and review evidence for approved exceptions.
