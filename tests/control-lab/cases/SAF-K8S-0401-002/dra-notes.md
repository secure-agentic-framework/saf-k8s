# Dynamic Resource Allocation authorization audit

Run `python3 lab.py test SAF-K8S-0401-002 --docker-context desktop-linux` with
the revised catalog. The original catalog digest still selects the ConfigMap
binding audit alone. The revised digest selects both the original audit and
this DRA permission matrix.

The Kubernetes v1.36.1 API server evaluates real SubjectAccessReview requests
for synthetic roles. A role with `resourceclaims/status` does not receive the
binding or driver permission. Scheduler and allocation writers use binding
verbs. Node-local and multi-node drivers use their respective node-aware verbs
for an explicitly named driver. The cases verify ordinary status, intended
binding or driver grants, wrong-driver and wrong-verb denials, and tenant
isolation.

These reviews exercise authorization tuples, without creating claims or writing
their status. Native request construction, healthy component operation and
production role inventory are separate evidence. The framework retains
`verified/SAF-K8S-0401-002.json` at the tested catalog revision.

- [Kubernetes v1.36 Dynamic Resource Allocation hardening](https://v1-36.docs.kubernetes.io/docs/concepts/security/hardening-guide/dynamic-resource-allocation/)
- [Kubernetes v1.36 SubjectAccessReview](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/authorization-resources/subject-access-review-v1/)
