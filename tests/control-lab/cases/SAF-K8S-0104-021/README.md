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

The catalog lists the API server, kubelets, controller-manager, scheduler, and
administrative clients. Kubernetes also specifies kube-proxy skew relative to
the API server and its colocated kubelet. A separate catalog follow-up tracks
expanding the listed coverage. The evaluator uses the upstream Version Skew
Policy. Kubernetes deployment tools can impose stricter requirements.

```sh
python3 lab.py test SAF-K8S-0104-021 --docker-context desktop-linux
```

In the framework repository use `python3 tests/control-lab/lab.py` with the same
arguments.

- [Pinned SAF-K8S control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0104-021.md)
- [Kubernetes v1.36 Version Skew Policy](https://v1-36.docs.kubernetes.io/releases/version-skew-policy/)
- [Kubernetes v1.36 kubeadm guidance](https://v1-36.docs.kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/)
