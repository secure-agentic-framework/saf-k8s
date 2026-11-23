# SAF-K8S-0402-011 — Cross-environment static credential prohibition

From the framework repository, run:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0402-011 --docker-context desktop-linux
```

The test creates three labeled namespaces in a fresh Kubernetes v1.36.1 Kind cluster. A native ValidatingAdmissionPolicy evaluates explicitly declared Secret type and scope metadata. All Secret fixtures are empty.

- **Red.** The baseline allows the declared cross-environment Secret on create and a local-to-cross-environment scope label transition on update.
- **Green.** With the policy active, the same declaration and transition are rejected in both inference profiles. Confirm that denied objects are absent and original local Secret state persists.
- **Permitted.** An unrelated local training Secret can still be stored after the policy is active.

The live case covers declared metadata and namespace profiles. Production review needs evidence of label governance, static credential inventory across clusters, and actual federated issuance. Metadata policy cannot infer credential contents, recognize all undeclared injection paths, or discover replication in other clusters.

[Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/) · [Kubernetes v1.36 Secrets](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/secret/)
