# SAF-K8S-0103-012 Effective controller permission scope

The fixture represents enabled service operations, a disabled route controller and separately owned storage actions with public records in Kind. It measures actual API decisions before and after narrowing a namespaced role, then confirms each approved identity can still perform its own operation. It demonstrates a permissions assessment pattern. Cloud IAM policies, provider assignments and unavoidable scope exceptions require separate deployment evidence.

## Adopter verification

1. Inventory the provider, Kubernetes and cloud-controller component
   versions. Record each enabled controller and assign ownership of
   networking, load-balancer, route, and storage operations.
2. Resolve the runtime's effective provider principal and policy sources.
   Include inherited and direct grants, resource policy, deny rules, and
   supported conditions. Record provider-owned boundaries and evidence
   availability.
3. Map each enabled duty to approved actions, resources and conditions.
   Use the provider's supported policy inspection or simulation, then
   confirm the intended action and unrelated denial in an approved test
   account. Retain the principal, decision and audit reference.
4. Review Kubernetes API RBAC separately. Record any provider exception
   with its owner, scope, compensating restriction, and review date.

- [Kubernetes v1.36 Cloud Controller Manager](https://v1-36.docs.kubernetes.io/docs/concepts/architecture/cloud-controller/)
- [Kubernetes v1.36 RBAC authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
