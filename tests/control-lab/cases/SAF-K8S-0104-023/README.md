# SAF-K8S-0104-023 Stage-based review of production feature gates

This case checks synthetic governance records against the Kubernetes v1.36.1
feature-gate registry. It starts a disposable kind cluster and submits records
as ConfigMaps in the fixture namespace. The same incomplete alpha record is
admitted before the policy is installed and denied by the policy afterward.
The policy accepts complete alpha and beta records and rejects records with
expired, missing, or version-mismatched approval metadata.

Run the case with the pinned Kubernetes node image and the Docker context
configured for your workstation.

```sh
python3 lab.py test SAF-K8S-0104-023 --docker-context desktop-linux
```

The [original control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0104-023.md)
requires documented production approval and security risk assessment for alpha
and beta features. The control digest is `82c1c6d23330706e6e186a332144a2459b299391fe6608c69c98af86258415e6`.

The two fixture gates are `ContainerStopSignals` (alpha since v1.33) and
`PodLevelResources` (beta in v1.36.1). The extra architecture review and tracked
exception for alpha are example criteria. The cutoff date is fixed to make the
expiry cases reproducible.

The policy validates synthetic records in one namespace. The test leaves
component feature-gate settings intact. Real risk assessments, approver
authority, review schedules, managed service behavior and production deployment
remain to be verified separately.

- [Kubernetes v1.36.1 feature-gate registry](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/features/kube_features.go)
- [Kubernetes v1.36 feature-gate stages and lifecycle](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/)
- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
