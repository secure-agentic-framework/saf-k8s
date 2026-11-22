# SAF-K8S-0104-009 — Feature-gate lifecycle transition tracking

```sh
python3 lab.py test SAF-K8S-0104-009 --docker-context desktop-linux
```

This case verifies kubelet gate transitions using source-derived upgrade
fixtures and the kubelet binary supplied by the pinned kind v1.36.1 image.

| Transition | Tested response |
| --- | --- |
| `KubeletCgroupDriverFromCRI` locked to its enabled default since v1.34 | The parser rejects `false`. The recognized default `true` reaches the config-file sentinel. |
| `DevicePluginCDIDevices` removed in v1.34 | The parser identifies the old setting as an unrecognized feature gate. |
| `GitRepoVolumeDriver` locked to its disabled default in v1.36 | The parser rejects `true`; `false` reaches the config-file sentinel. |
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

## v1.36 `gitRepo` lifecycle extension

The v1.36.0 tagged feature-gate registry records `GitRepoVolumeDriver` with a
false default and `LockToDefault: true` (the v1.33 transition made it deprecated
and default-off). The existing sentinel pattern now also supplies
`GitRepoVolumeDriver=true` and requires kubelet to reject it as locked to false;
`GitRepoVolumeDriver=false` must reach the intentionally impossible
`/dev/null/...` config path. Both commands run only as short-lived parser
invocations. The check does not start a node kubelet, enable the driver, or test
gitRepo runtime behavior.

The driver lifecycle and API schema are separate source assertions. In the
official v1.36.0 OpenAPI document,
`/definitions/io.k8s.api.core.v1.Volume/properties/gitRepo` remains present and
references `GitRepoVolumeSource`. The tagged v1 API type independently retains
`json:"gitRepo,omitempty"`. This extension therefore treats the field as
available to admission even though the kubelet driver gate is locked off.

`gitrepo-admission-policy.yaml` scopes Pod CREATE and UPDATE validation to the
runner's `saf-test` namespace. The Kubernetes v1.36.1 API accepted the inert
`gitRepo` field on CREATE before the policy. Once the policy and binding took
effect, the identical server-side dry-run returned the expected policy denial.
The supported `emptyDir` counterpart passed. Each Pod request uses server-side
dry-run, and the runner removes the disposable cluster afterward.

- [Kubelet v1.36.1 startup and validation order](https://github.com/kubernetes/kubernetes/blob/v1.36.1/cmd/kubelet/app/server.go)
- [Kubernetes v1.36.1 feature gate registry](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/features/kube_features.go)
- [Kubernetes v1.36.0 feature gate registry](https://github.com/kubernetes/kubernetes/blob/v1.36.0/pkg/features/kube_features.go) — `GitRepoVolumeDriver` is locked to its false default.
- [Kubernetes v1.36.0 OpenAPI schema](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.36.0/api/openapi-spec/swagger.json) — inspect `definitions.io.k8s.api.core.v1.Volume.properties.gitRepo` independently of the feature gate.
- [Kubernetes v1.36.0 core/v1 API type](https://github.com/kubernetes/kubernetes/blob/v1.36.0/staging/src/k8s.io/api/core/v1/types.go) — `VolumeSource.GitRepo` retains the `gitRepo` JSON field.
- [Kubernetes v1.36.0 changelog](https://github.com/kubernetes/kubernetes/blob/v1.36.0/CHANGELOG/CHANGELOG-1.36.md) — disabled with no option to turn it back on.
- [Kubernetes v1.34.0 changelog](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/CHANGELOG/CHANGELOG-1.34.md)
- [Kubernetes v1.37.1 feature gate registry](https://github.com/kubernetes/kubernetes/blob/v1.37.1/pkg/features/kube_features.go)
