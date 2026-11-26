# Verify external-service policy boundaries on Kind

```sh
python3 lab.py test SAF-K8S-0704-005 --docker-context desktop-linux
```

Two case-owned endpoints serve inert markers. Kubernetes admission recognizes
only the allowed service declaration for each fixture namespace. NetworkPolicy
independently limits actual connections to the approved endpoint and blocks
both endpoints from the restricted namespace.

The case uses invented policy decisions and in-cluster addresses. External
provider approvals, data handling, credential governance, and deployed egress
and monitoring require their own evidence.

## Approval tuple

The five checks cover three service and network observations and two aggregate admission comparisons. A second case-owned
ValidatingAdmissionPolicy is bound only to the synthetic standard namespace.
Before it is enabled, server-side dry-run Pod CREATE requests accept the exact
approved tuple and four one-field variants. After it is enabled, the exact
tuple is admitted and each variant is denied with the policy's exact message:

- local service identifier: `approved-service` vs `comparison-service`;
- declared purpose: `inference` vs `training`;
- declared information class: `public` vs `restricted`;
- Pod `spec.serviceAccountName`: `fixture-approved-client` vs
  `fixture-unapproved-client`.

Both synthetic ServiceAccounts are owned by the fixture and have no RBAC
grants. Dry-run Pods set `automountServiceAccountToken: false` and are never
stored, scheduled, or used to contact an endpoint. The service, purpose and
information-class labels are inert fixture data. The service-account check
validates the workload identity declared on the Pod object. The request author and effective workload identity are verified separately in the adopting deployment.
All marker endpoints remain local to the owned Kind cluster. No external
provider, DNS name, credential, contract, TLS session, or real data is used.

## Verify an adopting deployment

1. Maintain a versioned external-service inventory: provider/service, approved endpoint and owner, data/purpose classes, authorized workload or user identities, required provider controls, legal/contract approval, and expiry/review trigger. Link each entry to the accountable risk/legal/security approval.
2. Map every consumer and actual egress route. Record the policy enforcement point (admission, CNI, gateway or application), DNS and TLS identity validation, permitted ports/protocols, credential scope, and any alternate route. Verify one approved request and one denied service/purpose/data-class/identity case using controlled synthetic data in approved nonproduction.
3. Independently verify the effective production policy at the actual provider boundary: admitted workload identity and purpose/data authorization; DNS resolution; certificate chain/expected service identity; egress allow/deny; and that the provider is the approved endpoint. Record CNI/gateway version and policy ownership.
4. Preserve provider terms/assurance and audit evidence: data processing/use restrictions, retention/training terms where applicable, incident obligations, credential issuance/scope/rotation, request/response audit controls and log retention. Redact secrets and sensitive payloads from evidence.
5. Reconcile approved inventory against all deployed consumers and routes; review after provider, policy, data class, identity, DNS/TLS, contract or network changes. Record exceptions with owner, scope, expiry and approved compensating controls. Keep local five-check receipt labeled as portable local mechanism evidence.

## Record provider enforcement and adopted scope

Keep a dated service register with the actual provider, authorization
reference, approved workloads, endpoint identity, information classes,
allowed purpose, review trigger and exception expiry. Verify approval
of any applicable processing, retention and secondary-use terms.

Record the deployed CNI or gateway version, enabled policy feature,
covered node pools, traffic interfaces and address families. Verify
the documented enforcement boundary and independently observe the
approved route and a refused route. Demonstrate requester or provider
identity at its actual verifier, and correlate the decision with the
destination's approved audit evidence. Kubernetes Pod service account
selection, runtime egress and approval records each have their own
evidence source. Revalidate after a policy, provider, route, identity,
data-class or terms change.

[Kubernetes NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/),
[Amazon EKS network policy](https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy.html),
[GKE network policy](https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy),
and [AKS network policy](https://learn.microsoft.com/en-us/azure/aks/use-network-policies).
