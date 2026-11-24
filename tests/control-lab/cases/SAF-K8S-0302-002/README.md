# SAF-K8S-0302-002 — Capability boundary reference case

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0302-002 --docker-context desktop-linux
```

The admission policy requires every regular, init, and ephemeral container to
drop `ALL`. Added capabilities are limited to `CHOWN` and `NET_BIND_SERVICE`.
Those additions are policy-approved examples only; this case does not claim
they are needed by a workload. Every negative manifest, including the
ephemeral-container subresource request, is sent as a server dry-run. A
capability outside the allowlist is never persisted or launched.

Four BusyBox probes compare the bounding and effective capability masks of the
container's first process. All set and check the namespaced
`net.ipv4.ip_unprivileged_port_start` threshold at 1024. Both drop-all probes
report empty masks and fail to bind port 80. With `NET_BIND_SERVICE` added,
UID 65534 gets the bounding bit, has an empty effective mask, and still cannot
bind the port on this pinned runtime. The isolated container UID 0 comparison
has the bit in both masks and binds `127.0.0.1:80` in its own Pod network
namespace. The listener is stopped immediately. The UID 0 sample is only a
capability comparison in the diagnostic namespace. The native Restricted
admission probes use a separate namespace. Stable probe values are retained in
`capability-observations.json` in the run's evidence directory.

GPU approval, GPU-specific admission integration and real-device coverage
require separate evidence.

The additional checks exercise native Linux Restricted admission and the
digest-pinned NVIDIA device-plugin v0.20.2 argument parser in two short Kind
Jobs. The Jobs use help mode with no GPU resources, host access or kubelet
registration. Passing covers argument parsing and this admission comparison.
Hardware, driver/runtime compatibility and device allocation require their
own evidence. No device allocation is asserted here.

## Adopter verification

For each real Linux or accelerator workload, record the image digest, command,
device requests, node/runtime/driver versions, and the workload's actual
functional success criteria. Start with `drop: [ALL]`, run as nonroot where
supported, and inspect the actual workload process's `CapBnd` and `CapEff`
masks. Exercise
the real workload operation and record device access and application results.
If it fails, identify the specific denied operation and determine whether it
requires a Linux capability; add only that capability in an approved
workload-class policy, then repeat the same success and `CapEff` checks. Do not
infer a capability need from a device request or a successful device allocation.

Compare the minimum-capability result with the platform's native device-plugin
path, which should allocate only the declared device resources and required
device interfaces, and with CDI where the CRI/runtime and device plugin support
it. For NVIDIA CDI, verify the pinned plugin's documented device-list strategy,
compatible driver and CDI-enabled runtime, generated device specification,
and successful access from the intended workload. Record each alternative
tried, whether the workload met the same functional criteria, and the final
minimum `CapEff`/capability set. Capture hardware-specific results only on an
authorized adopter system; this portable fixture makes no hardware or
allocation claim.

[NVIDIA versioned flag definitions](https://github.com/NVIDIA/k8s-device-plugin/blob/v0.20.2/cmd/nvidia-device-plugin/main.go)
[Kubernetes v1.36 Restricted policy](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-standards/#restricted)
[Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
