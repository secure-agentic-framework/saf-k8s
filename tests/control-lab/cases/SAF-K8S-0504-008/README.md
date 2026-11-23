# SAF-K8S-0504-008 HTTP operation authorization

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0504-008 --docker-context desktop-linux
```

The test installs Cilium 1.20.5 with Envoy in an owned Kind cluster. A synthetic client sends individually mismatched methods, paths, and header values. Each reaches the owned backend before the CiliumNetworkPolicy is loaded. The exact requests receive HTTP 403 after the policy takes effect and cause no new backend arrivals. The reviewed method, path and header combination remains usable.

The test header is a fixed routing attribute. Deployed authorization also needs evidence of the workload identity, trusted header source, policy composition, protocol coverage and intended backend reachability.

[Cilium Layer 7 policies](https://docs.cilium.io/en/stable/security/policy/layer7/).
