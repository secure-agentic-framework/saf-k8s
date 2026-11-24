# SAF-K8S-0205-009 patched kube-proxy conntrack preservation

Run from the SAF-K8S checkout on a Linux/arm64 Docker engine with Kind v0.32.0.

```sh
image_id=$(/bin/sh tests/control-lab/build-v1.36.6-node.sh /tmp/saf-k8s-patched-node)
python3 tests/control-lab/cases/SAF-K8S-0205-009/kube-proxy-conntrack-preservation.py \
  --local-node-image "$image_id"
```

The fixture creates one upstream v1.36.6 Kind node. It observes the
pre-existing conntrack capacity under the native proxy, configures a lower
request with optional timeout writes disabled, and observes the proxy after
a restricted rollout. It measures effective capabilities, the sysctl mount
mode, unchanged capacity, and ordinary requests through a new fixture
ClusterIP. The harness removes the cluster.

Provider builds, other kernels and dataplanes, and deployed daemon
configuration require separate evidence.

The upstream iptables launcher prepares symlinks inside its container root
filesystem. The restricted profile leaves that filesystem writable and
verifies the runtime’s separate read-only /proc/sys mount.
