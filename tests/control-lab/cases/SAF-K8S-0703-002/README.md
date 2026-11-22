# SAF-K8S-0703-002 — PodDisruptionBudgets and voluntary evictions

```sh
python3 lab.py test SAF-K8S-0703-002 --docker-context desktop-linux
```

A three-replica Deployment runs in a disposable Kubernetes v1.36.1 cluster.
The case sends authorized voluntary Eviction requests through the live API
server. Without a matching budget, the API accepts a request and the
Deployment replaces the affected Pod. With a matching budget requiring all
three replicas, the observed allowance is zero and the API returns HTTP 429
while the affected Pod remains Ready. Changing the requirement to two
replicas makes one disruption available. The API accepts one eviction and
the Deployment restores three healthy replicas.

Kubernetes applies this budget through the Eviction API. Resilience to
involuntary disruption, deployment rollouts and direct deletion behavior,
actual production selectors and maintenance paths, and exception coverage
are separate evidence obligations.

- [Kubernetes v1.36 Disruptions and budgets](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/pods/disruptions/)
- [Kubernetes v1.36 API-initiated Eviction](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/api-eviction/)
- [Kubernetes v1.36.1 Eviction API server implementation](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/registry/core/pod/storage/eviction.go)
