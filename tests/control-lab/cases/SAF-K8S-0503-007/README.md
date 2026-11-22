# SAF-K8S-0503-007 — Ingress TLS termination and boundary configuration hardening

Run from the control lab root with Kind, Docker, Helm, OpenSSL, and Python
linked against a TLS 1.3-capable SSL library.

```sh
python3 lab.py test SAF-K8S-0503-007 --docker-context desktop-linux
```

On macOS, an OpenSSL-backed Python from Homebrew can be used if the system
Python lacks TLS 1.3. The published SAF-K8S checkout uses
`python3 tests/control-lab/lab.py test SAF-K8S-0503-007 --docker-context desktop-linux`.

The runner creates a Kubernetes v1.36.1 Kind cluster and allocates two loopback
ports. The case installs Gateway API Standard v1.6.3 and Traefik v3.7.19 from
Helm chart 42.4.1. It checks the Traefik deployment and runtime image digest.
One Gateway routes an exact host and path to an application that returns a
fixed marker. The same plaintext request returns the marker before HTTPS
configuration and receives a 404 after the Gateway reconciles.

The fixture CA and certificate authenticate the HTTPS endpoint for TLS 1.2 and
1.3. The test records the negotiated cipher and confirms rejection of TLS 1.1,
an unapproved TLS 1.2 cipher, an unrelated CA, and an incorrect hostname.
Requests with the trusted TLS identity and an unmatched HTTP host or path
return 404. The runner removes the cluster and keeps a receipt for each run.

This tests TLS termination and route selection for one Traefik Gateway. The
organization's approved TLS profile, production cert issuance and rotation,
actual controller inventory, migration coverage, and cloud exposure require
deployment evidence.

The Kubernetes community Ingress NGINX project retired on March 24, 2026.
F5 NGINX Ingress Controller is a distinct project. Envoy Gateway is the
Kubernetes Gateway API controller referenced by the updated examples.

## Sources

- [Original SAF-K8S control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0503-007.md)
- [Kubernetes v1.36 release notes](https://kubernetes.io/blog/2026/04/22/kubernetes-v1-36-release/#ingress-nginx-retirement)
- [Kubernetes Ingress TLS](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/ingress/#tls)
- [F5 migration guide](https://docs.nginx.com/nginx-ingress-controller/install/migrate-ingress-nginx/)
- [Envoy Gateway](https://gateway.envoyproxy.io/docs/concepts/gateway-api/)
- [Traefik Gateway API provider](https://doc.traefik.io/traefik/reference/routing-configuration/kubernetes/gateway-api/)
- [Traefik Helm chart v42.4.1](https://github.com/traefik/traefik-helm-chart/releases/tag/v42.4.1)
- [Gateway API v1.6.3](https://github.com/kubernetes-sigs/gateway-api/releases/tag/v1.6.3)
