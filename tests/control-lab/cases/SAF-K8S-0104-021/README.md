# SAF-K8S-0104-021 — Kubernetes component version skew compliance

The evaluator tests minor-version boundaries for the kubelet, kubectl,
controller-manager, scheduler, kube-proxy, and mixed-API-server HA relationships.
Nineteen synthetic samples cover 7 permitted boundaries and 12 rejected
cases, including the narrower rule for legacy node components below v1.25.
The rejected samples require the expected violation codes.

Read-only live inventory confirms the API server, kubelets, stock control-plane
components, and kube-proxy in disposable kind use v1.36.1. The test evaluates
the active kubectl client against the same policy. It checks one single-version
cluster and uses synthetic inputs for mixed-version HA. Actual production
inventories, provider and deployment-tool restrictions, and upgrade validation
need their own evidence.

The revised catalog also requires checking kube-proxy against the colocated
kubelet and every reachable API server, and cloud-controller-manager where
deployed. The revised case adds synthetic examples for the optional cloud
component and covers allowed and rejected relationships to individual HA
endpoints. Follow the upstream Version Skew Policy and any stricter
deployment-tool or provider requirements.

```sh
python3 lab.py test SAF-K8S-0104-021 --docker-context desktop-linux
```

In the framework repository use `python3 tests/control-lab/lab.py` with the same
arguments.

- [Pinned SAF-K8S control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0104-021.md)
- [Kubernetes v1.36 Version Skew Policy](https://v1-36.docs.kubernetes.io/releases/version-skew-policy/)
- [Kubernetes v1.36 kubeadm guidance](https://v1-36.docs.kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/)

The extended current-catalog case directly queries both owned HA API servers
over verified HTTPS. It inventories a control-plane pair, a worker, colocated
proxy and kubelet versions, controller and scheduler image versions and the
active admin client. It uses both backends as a conservative target set for
every audited fixture component. Removing a known backend observation makes
the evaluated inventory unverified. Mixed API server versions remain synthetic
policy cases in this fixture. The separate
[minor upgrade rehearsal](../SAF-K8S-0104-013/README.md) exercises a temporary
live kubelet/API server minor skew on a single control plane.

## Verify your implementation

1. Record every serving API server backend behind each endpoint. Verify
   the actual endpoint and version from approved provider inventory or
   direct component evidence, and record the topology and observation time.
   A load-balanced version reply identifies only the backend that answered.
2. Record component identity, running version and each reachable backend for
   controller managers, schedulers, kubelets, proxies and administrative
   clients. Link each proxy to its colocated kubelet. Where cloud-controller
   management is in use, include its version, support rules and reachable
   backends. Record any unavailable provider evidence as unverified.
3. Evaluate the range supported against all reachable API servers and check
   the API server spread itself. Apply exact release and distribution skew
   requirements and record any tighter upgrade-tool or provider prerequisites.
   Repeat during an authorized representative upgrade at each mixed-version
   stage and record the resulting compatibility decision.
4. Retain scoped endpoint inventory provenance, component observations,
   affected pairs, policy versions, exception ownership and upgrade evidence.
   Preserve pending results when a topology, backend or component version
   cannot be confirmed.
