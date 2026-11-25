# SAF-K8S-0103-001 — Bound and legacy service account tokens

Run against two disposable Kubernetes v1.36.1 kind profiles.

```sh
python3 lab.py test SAF-K8S-0103-001
```

A new service account has no auto-generated token Secret in either profile.
The stock controller-manager still populates a case-owned, explicitly
requested legacy Secret. A second profile appends the legacy controller
exclusion to the stock controller list. The live process has the flag and
still populates the fixture. Kubernetes v1.36.1 starts this controller
through a separate initialization path.

The case applies the namespace-scoped ValidatingAdmissionPolicy pattern
also covered by SAF-K8S-0402-020. The same Secret create then returns the
policy's explicit denial. A dry-run non-token Secret remains allowed. The
probe records field presence and immediately deletes the legacy fixture.

Both profiles run an unprivileged Pod with a projected service account
token. The second does so with admission active. The Pod observes the
configured audience, short expiration, workload UID and service account
subject and emits only four booleans. The API server issues the bound token
through TokenRequest and the kubelet delivers it.

The policy targets the test namespace. Deployment coverage, approved
legacy exceptions and expiry require separate operational evidence.

- [Kubernetes v1.36 managing service accounts](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
- [Kubernetes v1.36 Service Accounts](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/)
- [Kubernetes v1.36.1 controller construction](https://github.com/kubernetes/kubernetes/blob/v1.36.1/cmd/kube-controller-manager/app/controllermanager.go)
- [Kubernetes v1.36 validating admission policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)

## Adopter verification

1. Record the Kubernetes release and managed-service responsibilities, API
   server token issuer, approved audiences and lifetime policy, and projected
   TokenRequest paths for each governed workload class.
2. In a disposable namespace or equivalent approved environment, create a
   fresh service account and verify automatic legacy Secret absence. Exercise
   the effective admission policy against an unapproved explicit legacy token
   Secret and retain the policy decision. Review applicable exceptions, actor,
   namespace or object scope, duration, and verified expiry independently.
3. In the intended workload, inspect only sanitized projected-token claims.
   Compare expiration, audience, issuer and object binding with the policy and
   verify the allowed API operation still succeeds. Record evidence of renewals
   and application credential refresh separately when required.
4. For each runtime or provider release, retain effective configuration and
   contract evidence for TokenRequest, projection and admission. Coordinate
   version or feature-gate policy through the linked upgrade control.

## Explicit exception expiry

A separate admission binding uses a case-owned namespace, an exact approved
Secret name and ServiceAccount, a synthetic approval reference and a
fixed-format cutoff. All comparison requests are server-side dry-runs.
The expected tuple passes before the modeled cutoff, is refused at and after
it, and passes again when the modeled time returns to the valid window.
Unlisted and partially matching tuples are refused. An ordinary Opaque Secret
remains admissible. Each request is followed by a NotFound check and a
namespace count confirming zero stored legacy token Secrets.

For adoption, verify the selected trusted clock and policy refresh, exact
exception ownership and expiry, and removal or revocation of legacy
credentials already created under an approved exception.
