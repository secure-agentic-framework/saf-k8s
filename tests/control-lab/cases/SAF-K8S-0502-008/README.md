# SAF-K8S-0502-008 — Network policy for AI traffic

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0502-008 --docker-context desktop-linux
```

The disposable kind v0.32.0 cluster runs Kubernetes v1.36.1 and bundled kindnet. The case first checks actual HTTP marker responses along each path. It then applies three reviewed policies and reads the specs back from the API.

- A training client can reach its own job at the lower bound, middle and upper bound of the TCP range. The adjacent port and a same-port peer from another job are denied. A reverse probe checks ingress isolation separately.
- The model client can reach the approved registry Pod. A distinct registry Pod becomes unreachable.
- The approved gateway can reach the inference Pod, and the client outside the gateway namespace is denied.

The fixture uses synthetic listeners. Deployed verification needs actual NCCL listening ports and transport, governed label assignments, parameter-server traffic, external registry allowlists, and gateway and storage paths. [Kubernetes NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/) · [Pinned kindnet policy engine](https://raw.githubusercontent.com/kubernetes-sigs/kube-network-policies/f67f0fb35e2b/pkg/networkpolicy/networkpolicy.go) · [NVIDIA NCCL networking](https://docs.nvidia.com/deeplearning/nccl/user-guide/docs/troubleshooting/networking_troubleshooting.html)
