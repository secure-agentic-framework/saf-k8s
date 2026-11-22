# SAF-K8S-0104-009 — Feature-gate lifecycle transition tracking

```sh
python3 lab.py test SAF-K8S-0104-009 --docker-context desktop-linux
```

This case verifies two kubelet gate transitions using source-derived upgrade
fixtures and the kubelet binary supplied by the pinned kind v1.36.1 image.

| Transition | Tested response |
| --- | --- |
| `KubeletCgroupDriverFromCRI` locked to its enabled default since v1.34 | The parser rejects `false`. The recognized default `true` reaches the config-file sentinel. |
| `DevicePluginCDIDevices` removed in v1.34 | The parser identifies the old setting as an unrecognized feature gate. |
| Stale configuration removed | The separate command reaches the config-file sentinel, and the cluster API remains ready. |

Every parser invocation ends before the binary can start a separate kubelet. It
uses an impossible config file under `/dev/null` to prove the valid flags passed
the gate checks. The existing kubelet and its configuration are untouched. Local
JSON fixtures verify detection in a flag or config observation and preserve an
unrelated setting. The v1.37.1 source still registers the locked gate despite the
older comment projecting removal in v1.37, so this case uses the tagged registry
and changelog to choose a different gate with confirmed removal.

The framework retains `verified/SAF-K8S-0104-009.json`. The primary Bead links
both runs and the separate operational evidence for production upgrades and
other components.

- [Kubelet v1.36.1 startup and validation order](https://github.com/kubernetes/kubernetes/blob/v1.36.1/cmd/kubelet/app/server.go)
- [Kubernetes v1.36.1 feature gate registry](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/features/kube_features.go)
- [Kubernetes v1.34.0 changelog](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/CHANGELOG/CHANGELOG-1.34.md)
- [Kubernetes v1.37.1 feature gate registry](https://github.com/kubernetes/kubernetes/blob/v1.37.1/pkg/features/kube_features.go)
