# SAF-K8S-0101-019 — API server AlwaysAllow prohibition

```sh
python3 lab.py test SAF-K8S-0101-019 --docker-context desktop-linux
```

The fixture inspects the running Kubernetes v1.36.1 API server's explicit
`Node,RBAC` configuration in a fresh Kind cluster. A genuine short-lived
ServiceAccount credential reads its named synthetic ConfigMap and
receives 403 for another ConfigMap.

A separate admission fixture submits harmless configuration records with
server-side dry-run. The same record is admitted before the policy and
rejected after enrollment. Three representations containing AlwaysAllow
receive the expected denial. A record containing the fixture's approved
`Node,RBAC` order is admitted. The runner's live authorization chain
remains the approved one for the whole test.

Deployment verification covers actual API server modes or structured
authorization configuration, provider restrictions, and the provisioning
and periodic review process that keeps AlwaysAllow out.

- [Kubernetes v1.36 authorization modes and ordering](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authorization/)
- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
