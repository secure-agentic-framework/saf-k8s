# SAF-K8S-0504-005 — Service mesh tuning and selected injection

Run `python3 lab.py test SAF-K8S-0504-005` from the control-lab directory.

The seven checks use one pinned Istio 1.32.0 instance in a disposable Kind
cluster. They compare actual injected Envoy CPU and memory specifications,
the bounded authorized mTLS route, and rejection of an invalid resource
configuration under server-side dry run. A separate inert Pod opts out using
the supported `sidecar.istio.io/inject: "false"` label. The selected Pod
has no sidecar and sends no traffic. The existing tuned backend keeps its
configured proxy and processes the same authorized requests.

The scratch supplement adds a case-local native Kubernetes
`ValidatingAdmissionPolicy` for that one opt-out Pod. It denies a bare opt-out
when its parameter record is absent, rejects records in an `expired` state or
bound to another workload name, and admits the exact inert fixture record.
The record requires exception ID, workload namespace/name, fixture purpose,
risk owner, approver label, justification, compensating-control description,
expiry date, and review ID. The policy checks these values as fixture data;
it does not authenticate an approver or risk owner, compare the expiry date to
the current time, or show that the described compensation is adequate in a
real deployment. The tested compensation is only that this Pod has no network
path and sends no requests. The separately tested meshed route remains active.

For adoption, verify who can approve and set injection exceptions, which
flows and node paths they affect, and the compensating transport policy.
Measure actual GPU training throughput and resource contention on the
approved deployment. Exercise the configured model-serving ingress controls
and document the approved thresholds and escalation path.

- [Istio 1.32 sidecar injection](https://istio.io/v1.32/docs/setup/additional-setup/sidecar-injection/)
- [Istio 1.32 annotations](https://istio.io/v1.32/docs/reference/config/annotations/)
- [Istio 1.32 performance guidance](https://istio.io/v1.32/docs/ops/deployment/performance-and-scalability/)
- [Kubernetes Validating Admission Policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)

With an approved record present, a dry-run Pod using a different harmless
command is refused. The fixture policy binds the exact command and pinned
image, excludes extra containers and host networking, and requires disabled
service-account token automount.
