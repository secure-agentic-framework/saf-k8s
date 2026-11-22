# SAF-K8S-0702-028 Classification-based pipeline admission

```sh
python3 lab.py test SAF-K8S-0702-028 --docker-context desktop-linux
```

The [catalog control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0702-028.md)
requires admission decisions to enforce required classification metadata
when pipeline resources are created or updated.

A scoped ValidatingAdmissionPolicy on Kubernetes v1.36.1 compares the Pod
template classification with the requirement recorded on the fixture
namespace. Missing and mismatched values reach the API on CREATE and UPDATE
before the policy is installed. After installation, the same requests fail
with the fixture policy's denial on both Deployments and suspended Jobs.
Matching values remain admissible. The case uses scale-zero Deployments,
suspended Jobs and server-side dry runs.

Production evidence must cover the real classifier, enrolled namespaces,
policy exceptions, and each deployed pipeline resource kind and relevant
update surface.

- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes v1.36 suspended Job template label updates](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/job/#mutable-scheduling-directives)
