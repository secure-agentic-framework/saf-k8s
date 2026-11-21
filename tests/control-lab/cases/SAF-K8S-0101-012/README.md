# SAF-K8S-0101-012 — API server TLS enforcement

## Coverage and comparison

This case distinguishes protocol-version enforcement from cipher-suite enforcement.
The primary cluster in `kind.yaml` uses the Kubernetes default TLS profile. The
case first checks that an approved ECDHE AES-GCM TLS 1.2 handshake succeeds there.
That is the red baseline observation: the request reaches the kube-apiserver TLS
listener and succeeds before the stricter minimum is applied.

The case then creates a temporary, case-owned comparison cluster with
`--tls-min-version=VersionTLS13`. The same TLS 1.2 handshake must fail with the
peer's `protocol_version` alert; a TLS 1.3 handshake with hostname and kubeconfig
CA verification must succeed. The comparison demonstrates the version-floor
mechanism without offering TLS 1.0 or another obsolete protocol.

Cipher-profile behavior is checked independently in a second temporary reference
cluster configured for TLS 1.2 and the example ECDHE RSA/ECDSA AES-GCM allow-list.
The default listener must negotiate ECDHE-RSA-CHACHA20-POLY1305 before the change.
The reference listener must deny that same suite with a peer `handshake_failure`
alert and accept the approved RSA GCM suite. Each deploying organization supplies
its own approved suite profile.

All endpoints and CA data are read with targeted `kubectl config view --minify --raw`
JSONPath queries under the expected `kind-<cluster>` context. The case asserts
that context name and refuses any endpoint that is not HTTPS on an IP loopback.
It does not load raw kubeconfig client credentials into Python. TLS sockets are
closed in `finally` paths, and temporary profile clusters are deleted in their
context manager even when a probe fails.

The untrusted-CA check is explicitly a **client-side validation** oracle: a
client with no trust anchors rejects the server chain. It says nothing about
whether the server rejects an untrusted client certificate.

## Scope gaps

This case covers only the client-facing kube-apiserver TLS listener in local kind
clusters. It does not establish TLS settings or certificate trust on API-server
outbound connections to etcd, kubelets, aggregated API servers, admission
webhooks, other service-specific integrations, production load balancers, or
provider-managed termination points. Those require separate service/provider
evidence and checks at each actual connection endpoint.

The CA check establishes that the case client trusts the chain in generated
kubeconfig. It does not establish organization PKI governance, certificate
issuance, rotation, revocation, or the trust stores of other clients. No current
production configuration is inferred from these local profiles.

## Supported versions

- Kubernetes / kind node image: v1.36.1, pinned by `lab.py` to
  `kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`.
- TLS behavior flags: Kubernetes v1.36 documentation, linked below.
- TLS client: Python `ssl` and its linked TLS library must support TLS 1.2 and TLS
  1.3, offer the selected GCM and ChaCha20 ciphers, and expose peer alerts.
  Unsupported local protocols or ciphers block the corresponding observation.

## Primary references

- Pinned catalog control: SAF-K8S-0101-012 at framework commit
  `133a8698a45e2b335b51728bf4c62f7bda98d15f`,
  `markdown/controls/SAF-K8S-0101-012.md`.
- [Kubernetes v1.36 kube-apiserver reference](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/),
  especially `--tls-min-version` and `--tls-cipher-suites`.

## Live verification

The lab run verified the version and cipher comparisons, CA trust, and cleanup
on Kubernetes 1.36.1 using Python 3.14 with OpenSSL 3.6.4. Use a Python interpreter
with TLS 1.3 support to reproduce the run.
