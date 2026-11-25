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

The backend extension uses the same owned Kind cluster for the normal API server
proxy-to-kubelet health request and a named ConfigMap read through etcd. It
compares each route with the intended CA, an unrelated fixture CA, and the
restored CA. The etcd case requires a native certificate error from the
replacement API server, an unavailable ConfigMap read, and a healthy etcd
endpoint. Separate endpoint probes record an authenticated TLS negotiation.
The generated private keys remain inside the temporary fixture directory and
owned cluster. The case demonstrates the tested self-managed configurations.

- [Kubernetes v1.36 control-plane communication](https://v1-36.docs.kubernetes.io/docs/concepts/architecture/control-plane-node-communication/)
- [Kubernetes v1.36 API server flags](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

## Backend TLS policy comparison

The owned kubelet is restarted with a TLS 1.3 listener floor. Direct,
CA-verified comparison handshakes show the original listener accepting
TLS 1.2, the changed listener refusing TLS 1.2 by protocol, and verified
TLS 1.3 still working. The API server's actual kubelet health proxy
continues to work after the restart.

The owned single-member etcd comparison uses a TLS 1.2-only listener and
a single approved suite. The original listener accepts another fixture
suite. After replacement, the same excluded suite receives a handshake
alert, and TLS 1.3 receives a protocol-version alert. The approved suite,
authenticated endpoint health, and a new API write and read succeed.

The backend constraints and successful operations establish what each
route can negotiate under the fixture settings. The kubelet listener
floor does not identify its TLS 1.3 cipher per request. Apply the
organization's policy and repeat the allowed and excluded comparisons
for each applicable deployment path. See the companion
[API extension TLS case](../SAF-K8S-0404-002/README.md) for negotiated
TLS on actual aggregation and admission webhook requests.

- [Kubernetes v1.36 kubelet TLS settings](https://v1-36.docs.kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/)
- [etcd v3.6 TLS settings](https://etcd.io/docs/v3.6/op-guide/configuration/)

## Replay prerequisite

Run the case with PyYAML and a Python build that reports TLS 1.3 support. Verify the
interpreter that will invoke the runner with
`python3 -c 'import ssl, yaml; print(ssl.OPENSSL_VERSION, ssl.HAS_TLSv1_3)'`.

## Adopter verification

Record the Kubernetes release, service and tier, endpoint type, assessment
time, and approved PKI and TLS policy. Record the approving owner, allowed
protocols and TLS 1.2 cipher suites, certificate identity rules, rotation
expectations, and any exception. Treat a provider-managed CA as approved
only if the organization explicitly approves that trust policy.

Inventory the client-to-API, API-to-kubelet, API-to-etcd, aggregation, and
webhook connection paths that apply. Include TLS terminations at gateways,
proxies, or tunnels. For each path, record the peer names, enforcing settings,
trust roots, applicable protocol and cipher policy, rotation responsibility,
and evidence source. For self-managed servers compare approved source with
the effective process configuration. Review the outbound client trust
configuration separately from the API server listener.

From an approved vantage, confirm the selected kubeconfig context and API
endpoint. If the policy permits TLS 1.2 and the endpoint is DNS-named,
confirm one allowed negotiation using the applicable documented CA. Use
the selected service endpoint and CA through the normal approved access
path. Record the protocol, cipher, and verification result.

```sh
openssl s_client -connect "${API_HOST}:${API_PORT}" -servername "$API_HOST" \
  -verify_hostname "$API_HOST" -CAfile "$API_CA_FILE" -verify_return_error \
  -tls1_2 -brief </dev/null
```

For IP endpoints validate the IP subject alternative name with the applicable
client option. Use the relevant policy and library options for other allowed
protocols. Test excluded protocol, cipher, and CA settings in a controlled
fixture with an independent positive comparison. A successful allowed
negotiation is evidence for that endpoint, client, and vantage. For a managed
internal path, request release- and path-specific provider evidence for the
TLS floor, cipher policy, peer authentication, and certificate lifecycle.

- For EKS, collect the endpoint access configuration and cluster trust
  metadata and review the control-plane paths covered by provider evidence.
  [EKS endpoint documentation](https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html)
  [EKS control-plane architecture](https://docs.aws.amazon.com/eks/latest/best-practices/control-plane.html)
- For GKE, distinguish DNS and IP endpoint termination. Review the documented
  IP endpoint trust and control-plane-to-node TLS scope. [GKE network isolation](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/network-isolation)
  [GKE cluster trust](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/cluster-trust)
- For AKS, record the API endpoint and certificate and rotation scope. Match
  control-plane tunnel evidence to its actual peer path. [AKS certificate rotation](https://learn.microsoft.com/en-us/azure/aks/certificate-rotation)
  [AKS networking FAQ](https://learn.microsoft.com/en-us/azure/aks/faq)

Retain a path-by-path result with the version, assessment time, evidence
references, owner, and disposition. Record provider-attested evidence at its
documented scope. Mark undisclosed settings and untested paths unverified.
Retain only redacted configuration and handshake observations. Keep tokens,
private keys, and client credentials outside shared evidence.
