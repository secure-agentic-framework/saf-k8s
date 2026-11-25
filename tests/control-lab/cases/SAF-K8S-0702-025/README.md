# SAF-K8S-0702-025 — Tenant admission boundary enforcement

```sh
python3 lab.py test SAF-K8S-0702-025 --docker-context desktop-linux
```

The v1.36.1 fixture enrolls one namespace in two native admission policies.
The Deployment policy requires the resource and Pod template tenant IDs to
match the enrolled namespace. The RoleBinding policy requires explicit
ServiceAccount namespace references to match the binding namespace.

The administrator's server-side CREATE and UPDATE dry-runs show that the API
admits all four invalid declarations before applying the policies. The same
requests then receive the specific policy denials. Ordinary matching
Deployments and RoleBindings are created successfully. The original
Deployment template and binding subjects remain as saved after the update
checks. The mismatched binding subjects are submitted only in dry-run mode.

These policies cover two resource kinds and one reference type. The actual
tenant identity authority, all resource kinds and reference types, production
policy enrollment, and shared-service exception review require deployment
evidence.

- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)

## Adopter verification

1. Identify the actual tenant namespace and ownership sources, effective
   policy enrollment, applicable resource kinds and API versions.
2. Rehearse benign create and update requests under the actual deployed
   policy. Verify that mismatched tenant labels or subject namespaces
   receive the intended denial and matching declarations remain usable.
3. Review controller-generated resources, exemptions and failure policy.
   Retain approved exceptions with scope, owner and expiry.
4. Record active policy source and outcome evidence for periodic review.
