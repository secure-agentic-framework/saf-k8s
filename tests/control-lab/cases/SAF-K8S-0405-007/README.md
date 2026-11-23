# SAF-K8S-0405-007 Authenticated API path availability

Run by ID on fresh Kind. The case checks live API readiness and the
response classification of a small number of ordinary sequential reads
before and after applying a dedicated APF flow. The same authorized read
remains available. A single invalid credential and a single authenticated
but unauthorized read distinguish 401 from 403.

The fixture records no credential values. Assess provider endpoints,
service-level evidence, applicable protective controls and effective
capacity independently.

- [Kubernetes API Priority and Fairness](https://v1-36.docs.kubernetes.io/docs/concepts/cluster-administration/flow-control/)
- [Kubernetes API server health](https://v1-36.docs.kubernetes.io/docs/reference/using-api/health-checks/)
