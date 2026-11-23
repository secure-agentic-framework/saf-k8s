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
