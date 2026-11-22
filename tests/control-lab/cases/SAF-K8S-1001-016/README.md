# SAF-K8S-1001-016 — API-server audit coverage for AI-related resources

```sh
python3 lab.py test SAF-K8S-1001-016 --docker-context desktop-linux
```

Use `python3 tests/control-lab/lab.py` from the framework checkout. Each
run provisions two disposable Kubernetes v1.36.1 clusters. The baseline
policy records a known ConfigMap request and omits seven synthetic AI API
creates. The enabled policy adds five named rules for seven fixture CRDs.
They represent model records, training, pipelines, a GPU claim, serving,
checkpoints and snapshots.

The named rules log exact fixture create and patch requests at the
`Request` level. A broad `Metadata` fallback logs reads and an ordinary
ConfigMap without a body. The test also uses an earlier name-scoped `None`
rule and verifies its precedence. The test retains exact matching audit
events and the policy documents. The recorded request bodies consist only
of inert fixtures.

The [Kubernetes v1.36 audit policy documentation](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/#audit-policy)
and the [versioned audit API](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/pkg/apis/audit/v1/types.go)
specify first-match order and broad matching without an enumerated resource
list. Scope actual API groups, resources, verbs, stages and subresources
to the deployment. Evidence for production GPU, workflow and model systems,
managed-provider audit controls, and audit retention needs a separate review.
