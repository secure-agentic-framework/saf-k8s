# SAF-K8S-0504-002 — Service mesh mTLS and authorization policies

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0504-002 --docker-context desktop-linux
```

Istio 1.32 supports Kubernetes v1.36. The case verifies the official Istio release archive's SHA-256 before extracting the CLI and its Jaeger fixture. It installs the minimal mesh profile in a disposable v1.36.1 cluster and confines all probes to synthetic workloads and scoped policy. [Istio release](https://istio.io/latest/news/releases/1.32.x/announcing-1.32/), [Istio mutual TLS](https://istio.io/latest/docs/tasks/security/authentication/mtls-migration/).

Three unmeshed clients can reach the same fixture backend before enrollment. The two enrolled clients then make the same requests and the backend receives their distinct SPIFFE service-account identities. STRICT mTLS rejects the third client's formerly reachable plaintext request. A scoped authorization policy permits the approved identity and rejects the other with Envoy's RBAC response. The destination proxy exports HTTP 200 and 403 counters and labels a successful request `mutual_tls`.

The enrolled request carries a fixed fixture marker. Namespace-scoped Telemetry exports OTLP spans to the bundled Jaeger collector. The query under the sample's `/jaeger` base path must return both client and backend spans with the exact marker in one trace. All twelve assertions matched on the original and corrected catalog revisions, in `evidence/SAF-K8S-0504-002/20261122T100017Z-aeccf791/result.json` and `evidence/SAF-K8S-0504-002/20261122T100017Z-d279946f/result.json`. [Istio Jaeger integration](https://istio.io/latest/docs/tasks/observability/distributed-tracing/jaeger/).

The Helm comparison verifies the pinned Cilium 1.20.5 and 1.21.0-pre.4 chart
archives. The legacy values enable the mutual-auth switch in 1.20.5. The same
values still render SPIRE in 1.21.0-pre.4 while the switch is absent. This
corroborates the upstream deprecation and prerelease removal guidance.
Cilium WireGuard documents cross-node encryption. Same-node protection,
deployed namespace and protocol coverage, telemetry retention, and performance
require separate evidence. [Stable upgrade guide](https://docs.cilium.io/en/stable/operations/upgrade/),
[development upgrade guide](https://docs.cilium.io/en/latest/operations/upgrade/),
[Cilium WireGuard coverage](https://docs.cilium.io/en/stable/security/network/encryption-wireguard/).

The optional [Cilium runtime case](cilium/README.md) runs the stable
chart on a separate three-node Kind cluster and checks fixture SPIRE
authentication and active WireGuard peer state.

## Verify an adopting mesh

1. Record the control-plane and proxy versions, enabled mesh mode, workload
   identities, enrollment coverage, and any exceptions.
2. Inventory actual source to destination paths, including same-node and
   cross-node routes. For each, identify the mechanism that binds identity and
   the mechanism that protects traffic. Capture both independently when the
   chosen product separates them.
3. Verify the effective peer authentication and request authorization for
   normal approved comparisons against owned harmless routes. Record the
   receiving principal and policy decision.
4. Confirm protected request metrics, matching trace context at the client and
   server, actual collection and retention, and delivery to the intended
   operational consumer.
5. Measure resource use and connection overhead for the deployed mesh mode and
   representative workloads. Document gaps, compensating controls, owners and
   approved exceptions.

The paired Istio case checks one enrolled, traced request path. The companion
Cilium case records cross-node WireGuard receive counters and a distinct
same-node comparator. Review both boundaries for the paths used by the adopter.

### Versioned references

- [Istio 1.32 PeerAuthentication](https://istio.io/v1.32/docs/reference/config/security/peer_authentication/)
- [Istio 1.32 AuthorizationPolicy](https://istio.io/v1.32/docs/reference/config/security/authorization-policy/)
- [Istio 1.32 distributed tracing with Jaeger](https://istio.io/v1.32/docs/tasks/observability/distributed-tracing/jaeger/)
- [Cilium v1.20 WireGuard encryption](https://docs.cilium.io/en/v1.20/security/network/encryption-wireguard/)
- [Cilium v1.20 mutual authentication](https://docs.cilium.io/en/v1.20/network/servicemesh/mutual-authentication/mutual-authentication/)
- [Cilium v1.20 upgrade notes](https://docs.cilium.io/en/v1.20/operations/upgrade/)
