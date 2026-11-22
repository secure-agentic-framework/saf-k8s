# SAF-K8S-0104-022 — Non-default feature gate inventory for production clusters

```sh
python3 lab.py test SAF-K8S-0104-022 --docker-context desktop-linux
```

From the framework checkout, use `python3 tests/control-lab/lab.py` with the
same arguments.

The original inventory assertions remain on their pinned Kubernetes v1.36.1
clusters: stock API-server metrics are compared with the v1.36.1 default, and a
configured API server is checked against its effective feature-gate metric,
static-pod arguments, and matching server version.

The supervised live extension creates a separate, freshly named
`saf-lab-ndf-*` Kind cluster using the official
`kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5`
image. Its API endpoint is configured and checked as HTTPS on host loopback;
its kubeconfig is distinct from the v1.36.1 kubeconfig. The case uses only the
selected local Docker Unix-socket context and scopes peer node inspection and
cleanup to the exact `io.x-k8s.kind.cluster=<generated-name>` Docker label.
The peer has one opted-in worker and one explicitly disabled worker, configured
with per-node kubeadm v1beta4 `JoinConfiguration` patches. Both Node objects
must be Ready, report kubelet v1.37.0, and show the expected feature declaration
in kubelet-owned `status.declaredFeatures`. The server must report v1.37.0 and
all three peer nodes must report CRI `RuntimeReady=True`.

The scheduling comparison uses the pinned BusyBox 1.37.0 image and the same
small CPU/memory request. An ordinary sleeping control Pod must run on the
disabled worker. A feature Pod adds a container-level `RestartAllContainers`
rule for exit code 42, while its command sleeps for an hour and is never
expected to return. Targeting the disabled worker must leave it Pending with
the default scheduler's exact `NodeDeclaredFeatures` plugin reason:
`node(s) didn't match Pod's required features`. The otherwise identical
feature Pod, targeted to the worker whose Node reports the declaration, must
bind there and become Ready. The test never edits Node status and never causes
exit code 42. The owned v1.37 peer is deleted and its exact cluster-labeled
Docker containers are checked absent; the separate v1.36.1 baseline remains
under the existing harness lifecycle.

## Scope and interpretation

This tests pinned-version upgrade compatibility: kubelet publication and
default-scheduler placement when workers have different feature-gate states.
It does not turn the gate inventory into an authorization control, prove
production fleet coverage, validate custom schedulers or managed-node
providers, or exercise restart behavior. Production inventory and feature
lifecycle governance still need their own evidence under the relevant controls.

## Distinct follow-up observation: report refresh after restart

If a later supervised run needs to check refresh semantics, keep it a separate
observation and receipt. On a new disposable peer, record the enabled worker's
initial Ready status and feature list, remove any probe Pod, change only that
worker's kubelet gate to false using its kubeadm-managed node-local setting,
restart that kubelet, and wait for it to become Ready and publish a status
update. Record the post-restart feature list and timestamped ordinary Node
conditions, then create a new matching feature Pod pinned to that worker and
observe the scheduler filter reason. This follow-up tests restart-driven
snapshot refresh; it is not part of the initial side-by-side placement result
and must not patch Node status.

## Official references

- [Node Declared Features (Kubernetes v1.37)](https://v1-37.docs.kubernetes.io/docs/concepts/scheduling-eviction/node-declared-features/) — kubelet reporting and conditional default-scheduler placement.
- [Pod lifecycle (Kubernetes v1.37)](https://v1-37.docs.kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/) — `RestartAllContainers` behavior and exit-rule semantics.
- [Feature gates (Kubernetes v1.37)](https://v1-37.docs.kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/) — gate stage, defaults, and dependencies.
- [kubeadm v1beta4 configuration](https://kubernetes.io/docs/reference/config-api/kubeadm-config.v1beta4/) — node-local `nodeRegistration.kubeletExtraArgs` in `JoinConfiguration`.
- [Kind configuration](https://kind.sigs.k8s.io/docs/user/configuration/) — per-node config, `JoinConfiguration` patches, API server loopback address, and cluster creation options.
- [Tagged v1.37.0 scheduler plugin](https://github.com/kubernetes/kubernetes/blob/v1.37.0/pkg/scheduler/framework/plugins/nodedeclaredfeatures/nodedeclaredfeatures.go) — exact filter reason and inferred feature requirements.
- [Tagged v1.37.0 feature-gate registry](https://github.com/kubernetes/kubernetes/blob/v1.37.0/pkg/features/kube_features.go) — pinned gate lifecycle and dependency source.
