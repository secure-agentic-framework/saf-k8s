# SAF-K8S-0902-010 role-boundary fixture

This case exercises one narrow application boundary inside a disposable Kind cluster. It
creates an immutable ConfigMap, one Python Deployment, and one ClusterIP Service. The
digest-pinned Python image is already used by other control-lab cases. The fixture has no
model, model SDK, classifier, external call, or prompt-injection test content. Its recording
sink is local fixture state and returns the fixed answer `4`.

## Supervised run

From the control-lab checkout, after copying this directory to
`cases/SAF-K8S-0902-010/` and reviewing it, the harness entry point is:

```sh
python3 lab.py test SAF-K8S-0902-010
```

The harness must report `red`, `green`, and `positive` checks. Infrastructure failures are
reported as blocked and are not passing evidence. This scratch package does not create a
cluster; the user supervises the live run. The harness's node image is pinned in `lab.py`.

## Evidence boundary

* **Red, policy off:** one fixed ordinary request includes an extra `metadata` object with a
  benign `system: sample` label. The open schema accepts it, ignores it, and the local sink
  records only the trusted system/developer roles and user content.
* **Green, policy on:** an unknown role, a public `developer` field, and a public `system`
  field each receive HTTP 400. The recording sink remains at zero dispatches after those
  rejections.
* **Positive:** the ordinary user request succeeds; server-owned fixed context constructs
  system, developer, and user messages and increments the local sink once.

The green test is structured role construction and request-schema enforcement in this
fixture. It does not test content classification, detection accuracy, model execution,
production middleware, API gateway policy, upgrade lifecycle, or generalization to arbitrary
content. Kubernetes supplies the Pod and Service runtime, while the application code owns
request interpretation.

## Authenticated serving role

The fourth check verifies the authenticated role source. A
case-owned client Pod receives a normal projected ServiceAccount token. The inference
fixture sends that token to the same disposable cluster's Kubernetes API using the
TokenReview v1 endpoint over TLS with the mounted API CA. Its narrowly bound reviewer
ServiceAccount may create TokenReviews and cannot read Secrets. The fixture accepts only
the exact `saf-test/inference-user` ServiceAccount principal as the fixed `user` role.

The test calls the ClusterIP endpoint over HTTPS using a short-lived self-signed endpoint
certificate whose SAN is `saf-role-boundary`; the client trusts that exact certificate and
verifies the hostname. The private key is generated in a mode-0700 temporary directory,
written to a mode-0600 Secret manifest, passed to `kubectl` by file path, and never put in
command output or evidence. OpenSSL is a host prerequisite. The mock dispatcher still
returns only the fixed answer `4` and records only trusted fixed roles and benign content.

The grouped result requires: the API actually contains a projected client token volume;
the unauthenticated request returns 401 with dispatch count unchanged; the authenticated
request that claims harmless `developer` role returns 403 with dispatch count unchanged;
the positive request omits any client role and is accepted once using the internally mapped
`user` role; and the resulting trusted message roles are
`system`, `developer`, `user`. Evidence contains only statuses, fixed reason labels,
booleans, the effective fixture role and sink predicates. It contains no bearer token,
TLS private key, raw TokenReview object, or credential response.

This shows one native ServiceAccount-to-role binding through TokenReview in the owned
Kind fixture. It is not prompt-injection detection, classifier accuracy, model behavior,
production identity governance, gateway enforcement, or evidence of an adopted deployment.
The revised control requires serving-side enforcement of authenticated caller roles
and observed message boundaries. Verification of actual model behavior, production
message serialization, and any model-specific screening remains part of adoption.

Primary references:

- [Kubernetes v1.36 authentication](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authentication/): ServiceAccount tokens authenticate as `system:serviceaccount:<namespace>:<name>`.
- [Kubernetes TokenReview API](https://kubernetes.io/docs/reference/kubernetes-api/definitions/token-review-v1-authentication/): TokenReview authenticates a presented token and can constrain accepted audiences.
- [Kubernetes ServiceAccount guidance](https://kubernetes.io/docs/concepts/security/service-accounts/): projected tokens are bound and rotated; TokenReview is recommended for validating them.
- [NIST AI 100-2e2025 taxonomy](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
- [OWASP GenAI Project input and privilege controls](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
