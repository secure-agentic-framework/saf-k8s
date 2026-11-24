# SAF-K8S-0203-009 — Projected identity and scoped temporary credentials

```sh
python3 lab.py test SAF-K8S-0203-009 --docker-context desktop-linux
```

The first fixture uses Kubernetes TokenReview to compare a shared subject
mapping with a scoped one. The second fixture performs a real JWT exchange
against Vault's native auth endpoint using the pinned test API server issuer
and its public signing key. Wrong subject and audience are rejected. The
approved workload receives a nonrenewable, 16-second Vault credential. It
can read one seeded public marker, and requests for another marker or a
write are denied. The same credential loses access after the lease expires.
Vault runs with an in-memory store and a loopback-only listener within a
test Pod. The check uses test-only credentials and public marker data.

## Verify deployment applicability and evidence

1. Identify the managed provider, eligible workload, node-pool support, SDK
   version and exact identity mode. Confirm issuer or identity-agent trust,
   audience, Kubernetes namespace/service account, identity binding, and
   provider principal. Keep provider-specific trust boundaries separate.
2. Verify the application selects the expected principal with the supported
   SDK and a read-only identity operation against the chosen provider.
   Retain a redacted caller identity or audit event, then verify the allowed
   operation and a denied operation on approved disposable resources.
3. Record the credential type, issuance and expiry timestamps, renewal or
   rotation behavior, and evidence for an expired credential denial. Use
   ephemeral test resources and retain evidence without credential values.
4. Verify the SDK's fallback behavior and what alternate sources are
   reachable for the relevant ordinary and host-network workload profiles.
   Record separately which node identities are required for image pulls,
   platform agents, and other platform duties. Check provider IAM and
   metadata restrictions using the applicable approved verification process.

The lab demonstrates Kubernetes and Vault behavior. Any cloud provider
principal, IAM result, metadata boundary or SDK chain needs the adopter's
provider-specific evidence.

[Kubernetes v1.36 service account behavior](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/) ·
[Vault JWT roles and login](https://developer.hashicorp.com/vault/api-docs/auth/jwt) ·
[EKS Pod Identity](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html) ·
[GKE workload identity](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/workload-identity) ·
[AKS workload identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview)
