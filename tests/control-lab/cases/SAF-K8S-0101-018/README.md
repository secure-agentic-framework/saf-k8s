# SAF-K8S-0101-018 — API server anonymous authentication

```sh
python3 lab.py test SAF-K8S-0101-018
```

The current catalog revision selects the native v1.36.1 comparison. It
observes the default health result, disables anonymous authentication, and
observes the current kubelet startup failure counter and HTTP 401 for the
same TLS-verified health path. A dedicated client identity limited
to the health paths restores the static Pod's readiness. The control plane
remains Ready over two full probe intervals, and ordinary authenticated API
access still works. See [the authenticated probe case](HEALTHY-PROBE-FOLLOWUP.md).

The final comparison uses the upstream structured authentication
configuration with only three health paths enabled. It confirms anonymous
liveness HTTP 200 and anonymous version HTTP 401, while authorized health
and a namespace read still succeed. The runner verifies the local API server
CA and uses only fixed read-only paths for the unauthenticated observations.
It retains status and path information and deletes the disposable cluster.

## Adopter verification

1. Record the Kubernetes or provider release, API endpoint variants and
   access paths, scope, control owner, and effective settings. Track where
   a provider owns the authentication settings and which customer-side
   exposure or access settings apply. For self-managed clusters, confirm
   effective process flags or the authentication configuration and the
   approved health-probe design.
2. From an authorized vantage, use the documented TLS trust and a
   credential-free client for a single approved health path and an
   ordinary non-health endpoint such as `/version`. Record the status
   and selected endpoint, omit response bodies, and compare with the
   approved configuration. Use authenticated health and an authorized
   benign API read as positive comparisons. A transport failure, proxy
   denial, or absence of credentials in a captured output cannot establish
   an API-server HTTP 401.
3. Full disablement rejects both unauthenticated requests. For a documented
   provider-fixed health-only mode, verify the allowed health scope and
   non-health rejection separately. Record approved exceptions and applicable
   compensations, including endpoint reachability and any customer-managed
   authorization for that path. If policy requires full disablement, record
   the provider-fixed allowance as an outstanding policy gap.
4. Preserve the verified endpoint and TLS observations, redacted provider
   setting or attestation, scope, authority for each exception, and
   authenticated health and read results. Reassess on provider, version, or
   endpoint changes. Mark undisclosed settings and unchecked paths unverified.

The EKS documentation describes health-only anonymous access starting at
Kubernetes 1.32. GKE documents its `LIMITED` setting and applicable
versions. Read the actual service's version and effective settings before
selecting the expected observations.

- [Kubernetes v1.36 authentication](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-authenticator-configuration)
- [EKS anonymous authentication changes](https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions-extended.html#kubernetes-1.32)
- [GKE cluster hardening](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster)
- [Kubernetes v1.36 kubelet probe metrics](https://v1-36.docs.kubernetes.io/docs/reference/instrumentation/metrics/#prober-probe-total)
