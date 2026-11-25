# SAF-K8S-1005-022

This case exercises two bounded credential-containment procedures on a disposable Kind cluster
running Kubernetes v1.36.1. It uses one case-owned ServiceAccount and empty Opaque Secret marker
objects. `kubectl create token` issues two short-lived tokens bound to distinct marker Secret UIDs.
The bearer values remain in process memory only: the code sends TokenRequest and TokenReview
through a private subprocess path, excludes token-bearing requests and responses from the harness
command logger, and writes only boolean outcomes, fixed audience/identity metadata, and non-secret
object UIDs to `credential-observations.json`.

## Outcomes

- **Red:** TokenReview accepts both the old and replacement fixture tokens before retirement.
- **Green:** deleting the old token's case-owned marker makes its TokenReview unauthenticated while
  the independently bound replacement remains authenticated.
- **Positive:** recreating the old marker under the same name with a new UID does not revive the
  old token; the replacement stays valid. This confirms object-UID binding in the selected fixture.
- **External red/green/positive:** a pure in-memory verifier loads `fictional-provider.json`, first
  accepts three inert identity labels, then transitions one label from `active` to `retired`. The
  retired label becomes denied, the replacement stays accepted, and an unrelated label stays
  accepted. The labels are explicitly not credentials; there is no provider client, endpoint,
  network request, or live provider action.

The Kind node image is pinned by digest in `case.py` to match the official Kind v0.32.0 release's
Kubernetes v1.36.1 image. The supervisor's harness supplies this image to `kind create cluster`;
The runner uses its default single-node topology. No workload image or external feed is
used.

## Coverage and limits

The native observation verifies API-server TokenReview behavior for short-lived ServiceAccount
tokens explicitly bound to case-owned Secret UIDs. It does not use a `kubernetes.io/service-account-token`
legacy Secret, inspect tokens, test mounted projected tokens, rotate ServiceAccount identity,
exercise workload restart/isolation, or establish a production incident authorization workflow.
It is not evidence that every production verifier uses online TokenReview. Kubernetes documents
that offline JWT checks cannot determine whether a bound object is still current; consumers needing
current bound-object validity must use TokenReview.

The external fixture only demonstrates a desired retire-and-replace state transition in a fictional
offline verifier. Live provider-side revocation, propagation delays, credential discovery, provider
audit records, real token secrecy/storage, authorization, and workload pickup of the replacement
remain untested. This case does not establish production containment timing. No secrets or real
credentials are included.

## Official primary sources

- [Kubernetes v1.36 `kubectl create token` reference](https://v1-36.docs.kubernetes.io/docs/reference/kubectl/generated/kubectl_create/kubectl_create_token/) — short-lived TokenRequest interface, audiences, and supported bound-object flags.
- [Kubernetes ServiceAccount administration](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/) — Secret-bound token invalidation, object UID validation, and TokenReview verification. Kubernetes notes that an object pending deletion can remain valid until 60 seconds after its deletion timestamp; this case deletes marker Secrets without finalizers and polls the API outcome for up to 75 seconds.
- [Kubernetes TokenReview API](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/) — authenticated outcome and audience semantics.
- [Kind v0.32.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0) — defaults to Kubernetes v1.36.1 and publishes its digest-pinned node image.

## Verify an adopting implementation

Inventory issuer and credential type for each affected
workload and relying party. Under the approved incident procedure, retire the
old issuer-side credential, verify denial through Kubernetes and external
provider validation paths (including caches and existing sessions), issue a
replacement only to intended consumers, and show unrelated identities remain
valid. Record propagation timing, owner authorization, rollback constraints,
and sanitized audit outcomes.
