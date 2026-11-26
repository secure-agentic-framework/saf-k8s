# SAF-K8S-0504-005 — Service mesh tuning and selected injection

Run `python3 lab.py test SAF-K8S-0504-005` from the control-lab directory.

The seven checks use one pinned Istio 1.32.0 instance in a disposable Kind
cluster. They compare actual injected Envoy CPU and memory specifications,
the bounded authorized mTLS route, and rejection of an invalid resource
configuration under server-side dry run. A separate inert Pod opts out using
the supported `sidecar.istio.io/inject: "false"` label. The selected Pod
has no sidecar and sends no traffic. The existing tuned backend keeps its
configured proxy and processes the same authorized requests.

For adoption, verify who can approve and set injection exceptions, which
flows and node paths they affect, and the compensating transport policy.
Measure actual GPU training throughput and resource contention on the
approved deployment. Exercise the configured model-serving ingress controls
and document the approved thresholds and escalation path.

- [Istio 1.32 sidecar injection](https://istio.io/v1.32/docs/setup/additional-setup/sidecar-injection/)
- [Istio 1.32 annotations](https://istio.io/v1.32/docs/reference/config/annotations/)
- [Istio 1.32 performance guidance](https://istio.io/v1.32/docs/ops/deployment/performance-and-scalability/)
