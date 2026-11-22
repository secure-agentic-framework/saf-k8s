# SAF-K8S-0702-005 — Workload classification schema and quota scopes

```sh
python3 lab.py test SAF-K8S-0702-005 --docker-context desktop-linux
```

The case binds a native admission policy to one enrolled namespace. It checks
missing and unsupported values for each minimum category from the catalog.
The red arm sends the same Pod CREATE probes while the policy is inactive.
The green arm receives exact policy denials, and a dry-run verifies every
enumerated value is valid in its own classification category.

| Label | Governed values |
| --- | --- |
| `ai.kais.io/workload-type` | training, inference, preprocessing, evaluation, notebook |
| `ai.kais.io/data-sensitivity` | public, internal, confidential, restricted |
| `ai.kais.io/model-tier` | experimental, staging, production |

A native label selector distinguishes the two admitted fixture classes.
ResourceQuota rejects the classification key as an unsupported scope and
accepts the native PriorityClass scope. The built-in quota's successful
creation checks the API boundary. Quota consumption and classification
mapping require further evidence.

The related SAF-K8S-0702-009 case verifies classification on Pod and
controller-template CREATE and UPDATE. This case leaves additional labels,
annotation schemas, organization enrollment, traffic policy and production
audit collection open. The runner cleans up the entire disposable cluster.

- [Kubernetes v1.36 labels and selectors](https://v1-36.docs.kubernetes.io/docs/concepts/overview/working-with-objects/labels/)
- [Kubernetes v1.36 ResourceQuota scopes](https://v1-36.docs.kubernetes.io/docs/concepts/policy/resource-quotas/#quota-scopes)
- [Kubernetes v1.36 audit policy configuration](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
