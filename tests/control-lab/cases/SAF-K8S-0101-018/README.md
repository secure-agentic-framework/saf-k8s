# SAF-K8S-0101-018 — API server anonymous authentication disablement

## Coverage and comparison

The runner's disposable kind cluster is the default-profile baseline. The case
sends a standard unauthenticated HTTPS `GET /livez`, verifies the API server
certificate with that cluster's kubeconfig CA, and records only the method,
path, HTTP status, and fixed metadata confirming that no client certificate or
Authorization header was supplied. It does not read client keys, client
certificates, or tokens for this request. It makes no other anonymous request.

A second, collision-checked disposable kind profile sets
`--anonymous-auth=false`. The same CA-verified `GET /livez` must receive actual
HTTP 401. In both profiles, `kubectl get --raw=/livez` and an ordinary
`kubectl get namespace saf-test` must succeed using the runner's normal
authorized kubeconfig path. The test does not print or retain the health
response body. Both profiles are deleted, including partial creation cleanup.

The baseline observation is the red condition: the otherwise benign request
succeeds while anonymous authentication is enabled. The configured profile is
the green condition: the same request receives 401. Positive observations
confirm that authorized health and a normal Kubernetes API read remain usable.

## Catalog applicability and managed-provider coverage

The pinned control at framework commit
`133a8698a45e2b335b51728bf4c62f7bda98d15f` applies to production clusters and
to sensitive, shared, or production-path non-production clusters. Its scope
explicitly includes managed Kubernetes customer-exposed authentication
settings and compensating controls when provider-managed settings are fixed.
Its implementation surface names API-server manifest flags, managed service
security settings, provisioning templates, and periodic status assessment.

The local kind test covers only the self-managed API-server flag path. It does
not verify EKS, GKE, AKS, or another managed service. Where a managed provider
exposes an anonymous-authentication setting, evidence must show the actual
customer-side value and the API endpoint behavior. Where the provider fixes
that setting, alternative evidence is required by the pinned catalog scope:
document the provider constraint and validate the applicable compensating
controls on the customer-exposed API path. Provider documentation and
customer-side configuration evidence must be gathered for the actual service;
this kind result cannot substitute for them. No provider-specific exception
or universally available alternative is inferred here.

## Supported versions

- Case profile: Kubernetes v1.36.1, using the node image pinned in `lab.py`:
  `kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`.
- The case sets the `--anonymous-auth` kube-apiserver flag documented for
  Kubernetes v1.36. No other Kubernetes minor or managed control plane is
  claimed as tested.
- This implementation has not been run against kind in this task. Supervisor
  review and live execution remain outstanding.

## Primary references

- Pinned catalog control: `SAF-K8S-0101-018`, framework commit
  `133a8698a45e2b335b51728bf4c62f7bda98d15f`,
  `markdown/controls/SAF-K8S-0101-018.md`.
- [Kubernetes v1.36 authentication](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authentication/): anonymous request identity, default behavior, `--anonymous-auth=false`, and configurable anonymous paths.
- [Kubernetes v1.36 kube-apiserver flags](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/): `--anonymous-auth` default and behavior.

## Verification gaps

- No live cluster execution, HTTP observation, or cleanup result is recorded by
  this source-only implementation task.
- Production configuration, any management/provisioning drift, external API
  paths, load balancers or proxies, and provider-specific controls remain
  unverified.
- For a managed service, applicability and available configuration/alternative
  evidence must be determined against that provider's current service behavior
  and the deployed cluster. The generic control does not name providers or
  prescribe one universal compensating control.
- A 401 at `/livez` demonstrates that the unauthenticated request was not
  accepted by the configured API server. This test does not inspect audit
  identity attribution or prove that every API route, proxy path, or alternate
  authentication configuration rejects anonymous requests.
