# SAF-K8S-0703-012 patched namespace-selector scheduling

Run from the SAF-K8S checkout on a Linux/arm64 Docker engine with Kind v0.32.0.
Docker Desktop on macOS arm64 provides the tested engine.

```sh
image_id=$(/bin/sh tests/control-lab/build-v1.36.6-node.sh /tmp/saf-k8s-patched-node)
python3 tests/control-lab/cases/SAF-K8S-0703-012/scheduler-namespace-selector.py \
  --local-node-image "$image_id"
```

The test creates one control plane and two workers. Inert anchors with the
same labels run on separate workers in included and excluded namespaces.
The baseline selects both namespaces. With the `NotIn` selector, required
affinity admits the included anchor's worker and leaves the excluded
worker's probe unschedulable. Required anti-affinity makes the inverse
decisions. The receipt preserves the scheduler's conditions and selected
worker names. The harness removes the cluster.

The fixture covers the upstream v1.36.6 scheduler and one topology key.
Managed-provider backports, customized schedulers, and deployed
namespace-label authority need separate evidence.
