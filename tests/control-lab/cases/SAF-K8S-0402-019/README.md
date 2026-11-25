# SAF-K8S-0402-019 Dedicated workload service accounts

```sh
python3 lab.py test SAF-K8S-0402-019 --docker-context desktop-linux
```

The [catalog control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0402-019.md)
requires workload-specific identities and permissions. This case confirms
that Kubernetes v1.36.1 assigns the namespace's `default` ServiceAccount to a
Pod that omits the field. Two application Pods retain distinct explicit
assignments. Before the RoleBindings are added neither identity has its
fixture-specific permission. After the bindings take effect each Pod reads
its own inert ConfigMap marker. An authorized SelfSubjectAccessReview confirms
the other fixture's permission is absent. The probe sends only normal
authenticated API requests for permitted behavior and self-review.

The two application Pods use their mounted tokens inside normal HTTPS
requests to the disposable cluster's API. The uncredentialed defaulting
control does not need a token. Probe output contains only a response code and
the expected result. Kubernetes API identity and authorization are demonstrated
for these fixture permissions. Cloud IAM, X.509 services and enforcement
across deployed workloads need separate evidence.

- [Tagged v1.36.1 ServiceAccount admission](https://github.com/kubernetes/kubernetes/blob/v1.36.1/plugin/pkg/admission/serviceaccount/admission.go)
- [Tagged v1.36.1 bootstrap RBAC](https://github.com/kubernetes/kubernetes/blob/v1.36.1/plugin/pkg/auth/authorizer/rbac/bootstrappolicy/policy.go)
- [Kubernetes v0.36.1 authorization API types](https://github.com/kubernetes/api/blob/v0.36.1/authorization/v1/types.go)

## Adopter verification

1. Identify the running workload's assigned ServiceAccount and effective
   permissions, including the default identity and any template or
   fallback assignments.
2. Verify representative permitted and denied Kubernetes requests using
   the effective identity and exact resource scope.
3. Where federation applies, verify the actual provider issuer, audience,
   subject, namespace mapping and accepting principal. Rehearse the
   permitted provider action and a representative scope refusal.
4. Inspect alternate credential sources and retain sanitized decisions,
   provider audit references, responsible owner and review cadence.
