# SAF-K8S-0504-002 — Service mesh mTLS and authorization policies

```sh
python3 lab.py test SAF-K8S-0504-002 --docker-context desktop-linux
```

Istio 1.32 supports Kubernetes v1.36. The case verifies the official Istio release archive's SHA-256 before extracting the CLI and its Jaeger fixture. It installs the minimal mesh profile in a disposable v1.36.1 cluster and confines all probes to synthetic workloads and scoped policy. [Istio release](https://istio.io/latest/news/releases/1.32.x/announcing-1.32/), [Istio mutual TLS](https://istio.io/latest/docs/tasks/security/authentication/mtls-migration/).

Three unmeshed clients can reach the same fixture backend before enrollment. The two enrolled clients then make the same requests and the backend receives their distinct SPIFFE service-account identities. STRICT mTLS rejects the third client's formerly reachable plaintext request. A scoped authorization policy permits the approved identity and rejects the other with Envoy's RBAC response. The destination proxy exports HTTP 200 and 403 counters and labels a successful request `mutual_tls`.

The enrolled request carries a fixed fixture marker. Namespace-scoped Telemetry exports OTLP spans to the bundled Jaeger collector. The query under the sample's `/jaeger` base path must return both client and backend spans with the exact marker in one trace. All twelve assertions matched on the original and corrected catalog revisions, in `evidence/SAF-K8S-0504-002/20261122T100017Z-aeccf791/result.json` and `evidence/SAF-K8S-0504-002/20261122T100017Z-d279946f/result.json`. [Istio Jaeger integration](https://istio.io/latest/docs/tasks/observability/distributed-tracing/jaeger/).

The corrected catalog distinguishes Istio's in-band mTLS from Cilium's out-of-band peer authentication with separately configured encryption. Its source and implementation work are linked separately. This fixture covers the selected Istio workloads and HTTP path. Cilium transport behavior, other mesh implementations, actual namespace and protocol coverage, telemetry retention and performance require separate evidence. [Cilium mutual authentication](https://docs.cilium.io/en/stable/network/servicemesh/mutual-authentication/mutual-authentication/), [Linkerd authorization policy](https://linkerd.io/docs/reference/authorization-policy/).
