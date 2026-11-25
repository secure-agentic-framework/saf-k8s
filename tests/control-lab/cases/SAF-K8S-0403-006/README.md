# SAF-K8S-0403-006 Per-job credential scope

Run `python3 lab.py test SAF-K8S-0403-006` with the revision in the verified
result. Each owned Kubernetes Job mounts its own projected credential and
uses real API requests to read a fixture representing an individual resource.
The test observes the shared-grant baseline and replaces it with one grant
per approved resource. Scoped Job admission independently confirms identity
assignment and rejects the switched relationship.

Only public fixture markers and HTTP results are retained. The run verifies
the Kubernetes authorization boundary. Actual cloud IAM, Vault and service
resource authorization and orchestration templates require separate evidence.

- [Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes ServiceAccount token projection](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)

## Adopter verification

1. Identify the actual workload principal and effective credential source.
   Match its issuer, subject, provider binding, and approved workload
   template to the documented purpose.
2. Inventory direct and inherited grants, resource policies, trust,
   permission boundaries and provider ownership. Record exact allowed
   actions and resource scope in the accepting service.
3. In an approved rehearsal, demonstrate the required operation and
   representative refusals for unrelated resources and unauthorized
   operations. Record the resolved principal and provider audit event.
4. Inspect fallback sources and other paths to the same resource. Verify
   that the workload uses only the approved credential path, and record
   any time-bounded exceptions with their owner and review dates.
