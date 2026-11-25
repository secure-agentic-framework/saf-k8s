# SAF-K8S-0101-019 — API server AlwaysAllow prohibition

```sh
python3 lab.py test SAF-K8S-0101-019 --docker-context desktop-linux
```

The fixture inspects the running Kubernetes v1.36.1 API server's explicit
`Node,RBAC` configuration in a fresh Kind cluster. A genuine short-lived
ServiceAccount credential reads its named synthetic ConfigMap and
receives 403 for another ConfigMap.

The case installs a structured AuthorizationConfiguration containing the
same ordered Node and RBAC authorizers. It observes the running server's
explicit file argument and Ready state. The same credential still reads
its approved object and receives Kubernetes Forbidden for the comparison.

A namespace-scoped admission fixture evaluates harmless ConfigMap review
records with server dry-run. The same inert record is admitted before the
policy and rejected after enrollment. Three records containing prohibited
authorizer values receive the expected denial, and an approved record
is admitted. The inert structured-form record is a normalized string for
this policy demonstration. The live structured configuration comparison
uses the separate approved file.

## Adopter verification

1. Record the Kubernetes and provider versions, scoped API-server instances,
   authorized reviewers, and approved chain and policy revisions. Inspect the
   effective command and rendered deployment source for each instance.
   Review both argument forms and account for missing, duplicate, empty or
   conflicting settings. For the v1.36 flag route, the command reference
   lists AlwaysAllow as the default when no structured file is configured.
2. Identify the active configuration mechanism. When using the structured
   file, parse the actual versioned schema, resolve the mounted path, and
   verify the ordered `authorizers[].type` list and approved file hash
   on every instance. Check effective reloads and deployment drift.
   Prohibit AlwaysAllow wherever it appears in the effective chain.
3. Check the rendered provisioning artifact before upgrades and rollouts.
   Retain the approved source, rejection rule and exact effective
   configuration. For a runtime comparison using approved ordinary identities,
   confirm one harmless authorized decision and one expected denial. Preserve
   the exact authorization tuples, source, scope and time.
4. For a managed control plane, identify which authorization settings the
   provider publishes or attests for the deployed product and version. Verify
   customer-controlled RBAC, IAM, endpoint limits and audit collection as
   compensating evidence. Record the scope and review owner for each control.
   Mark the effective chain unverified if provider evidence omits it.

- [Kubernetes v1.36 authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authorization/)
- [Kubernetes v1.36 API-server flags](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
- [Kubernetes v1.36 API-server configuration schema](https://v1-36.docs.kubernetes.io/docs/reference/config-api/apiserver-config.v1/)
- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [EKS control-plane configuration](https://docs.aws.amazon.com/eks/latest/userguide/control-plane-configuration.html)
- [GKE cluster architecture](https://cloud.google.com/kubernetes-engine/docs/concepts/cluster-architecture)
- [AKS managed component policies](https://learn.microsoft.com/azure/aks/support-policies)
