# SAF-K8S-0402-006 Workload federation

Run `python3 lab.py test SAF-K8S-0402-006` against the catalog revision in the
verified result. Live Kind workloads mount a projected service account token
for a fixture-only audience. Kubernetes TokenReview validates the credential
and a scoped local exchange rule separately checks the subject. A native
admission policy rejects references to one designated static credential
Secret across volume and container input paths, including ephemeral updates.

The case checks actual Pod-bound token invalidation and preserves no token
values. Provider trust, authorization, rotation and fallback require
separate deployment evidence. AWS EKS Pod Identity associations, EKS IRSA,
GKE direct/linked identities and AKS identity paths have distinct
prerequisites and are scoped separately in the catalog.

- [Kubernetes service account administration](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
- [Amazon EKS workload identity mechanisms](https://docs.aws.amazon.com/eks/latest/userguide/service-accounts.html)
- [GKE Workload Identity Federation](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/workload-identity)
- [AKS Workload ID](https://learn.microsoft.com/azure/aks/workload-identity-overview)
