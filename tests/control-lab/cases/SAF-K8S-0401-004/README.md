# SAF-K8S-0401-004 — RBAC for operator custom resource instances

```sh
python3 lab.py test SAF-K8S-0401-004 --docker-context desktop-linux
```

The case uses two namespaced fixture CRDs in a synthetic API group and no
operator controller. The broad baseline grants routine instance operations
on both resources. The exact namespaced Role keeps create, update and delete
for one resource, and forbids those operations on the other. The checks
also cover the namespace boundary, status subresource, and absence of CRD
definition administration from the instance Role. A separate synthetic
administrator with an explicit status grant provides a permitted comparison.
The cluster is deleted after the run.

## Adopter verification

1. Inventory each installed operator's API groups, resource names, supported
   versions, scope, and subresources. Kubeflow Trainer v2 uses `TrainJob`;
   Training Operator v1 used resources such as `PyTorchJob`. Record API
   discovery for the actual KServe, Kubeflow, KubeRay, or Volcano release.
2. Review the effective permissions of the intended principals and the
   operator controller. Map each approved action to its group, resource,
   namespace and verb. Include `patch`, `deletecollection`, `status`, and
   `finalizers` where applicable, and review cluster-scoped resources and CRD
   registration separately.
3. Use authorized representative identities and harmless dry-run instance
   requests in an approved rehearsal scope. Pair permitted operations with
   refusals for an unapproved resource, namespace, or subresource. Confirm
   policies that depend on object fields through the applicable admission
   mechanism.
4. Retain redacted decisions and relevant audit references. Describe privilege
   review cadence and require a separately evidenced mandatory access control
   mechanism where relying on the composite NIST AC-3(15) mapping.

- [Kubernetes v1.36 custom resources](https://v1-36.docs.kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)
- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubeflow Trainer migration guide](https://trainer.kubeflow.org/en/latest/operator-guides/migration.html)
