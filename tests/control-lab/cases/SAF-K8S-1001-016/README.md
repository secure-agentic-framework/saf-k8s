# SAF-K8S-1001-016 — API-server audit coverage for AI-related resources

Run from the framework root.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1001-016 --docker-context desktop-linux
```

Each run provisions two disposable Kubernetes v1.36.1 clusters with an incomplete policy and a scoped policy. The incomplete policy audits the known ConfigMap operation and omits successful creates for seven synthetic AI API resources. The scoped policy logs exact creates, patches, updates and deletes at Request level, uses Metadata fallback for reads and for a same-resource create in another namespace, and checks a name-scoped None rule takes precedence. The request bodies consist of inert fixtures from seven invented CRDs. Audit records and policy documents are retained for comparison.

For adoption, inventory each applicable API group, resource, subresource, verb and namespace. Compare discovery and effective first-match policy against the material changes the system must log. Use harmless approved actions to verify the stage, level and minimized fields arriving at the authorized backend. Verify retention, access controls and export coverage for every adopted provider and correlate applicable lifecycle actions with documentation when required. The conditional Article 12(2) mapping covers only relevant logging of events in the applicable high-risk system.

[Kubernetes v1.36 audit policies](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/#audit-policy) · [Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689)
