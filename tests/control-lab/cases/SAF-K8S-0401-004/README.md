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

Production grants depend on installed API groups, plural resources, and
scope. For example, Kubeflow Trainer v2 uses `TrainJob`, while Training
Operator v1 used resource types such as `PyTorchJob`. Discover the real
KServe, Kubeflow, KubeRay or Volcano resources and evaluate their installed
versions, binding subjects and subresources before applying a policy.

- [Kubernetes v1.36 custom resources](https://v1-36.docs.kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)
- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubeflow Trainer migration guide](https://trainer.kubeflow.org/en/latest/operator-guides/migration.html)
