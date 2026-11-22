# SAF-K8S-0702-030 Automatic classification during model promotion

```sh
python3 lab.py test SAF-K8S-0702-030 --docker-context desktop-linux
```

The [catalog control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0702-030.md)
requires promotion automation to apply the classification required by the
target environment or artifact. The fixture uses a synthetic rank policy
and ConfigMaps containing invented artifact metadata.

Initially the high-sensitivity target carries an insufficient copied source
classification. An ordinary Kubernetes Job applies the higher label to the
target and records the decision, policy version, and time. An equal policy
preserves classification. When the target requirement is unknown, the Job
records the unresolved outcome and leaves the target unchanged. The source
remains unchanged in all three cases. The Job's service account can only
patch the three named fixture metadata objects.

Production evidence needs the real promotion controller, versioned policies,
ownership, artifact metadata integrity, and the actual decision record in
the deployed pipeline. SAF-K8S-0702-031 separately covers the production
promotion gate.

- [Kubernetes v1.36 Jobs](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/job/)
- [Kubernetes v1.36 RBAC resource names](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
