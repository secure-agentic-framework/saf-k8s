# SAF-K8S-0302-002 — Capability boundary reference case

The admission policy requires every regular, init, and ephemeral container to
drop `ALL`. Added capabilities are limited to `CHOWN` and `NET_BIND_SERVICE`.
Those additions are policy-approved examples only; this case does not claim
they are needed by a workload. Every negative manifest, including the
ephemeral-container subresource request, is sent as a server dry-run. A
capability outside the allowlist is never persisted or launched.

The sole persisted workload is a harmless BusyBox process with no added
capabilities. It reports `/proc/self/status`'s `CapEff` field, and the case
requires the observed mask to be zero. There is no elevated code or host mount.

GPU approval, any GPU-specific admission integration, and real-device coverage
are separate and untested here. This reference case makes no claim about GPU
authorization or a physical/virtual accelerator. Static case review alone is
not a runtime result; any later lab execution must retain its evidence
separately.

The additional checks exercise native Linux Restricted admission and the
digest-pinned NVIDIA device-plugin v0.20.2 argument parser in two short Kind
Jobs. The Jobs use help mode with no GPU resources, host access or kubelet
registration. Passing covers argument parsing and this admission comparison.
Hardware, driver/runtime compatibility and device allocation require their
own evidence.

[NVIDIA versioned flag definitions](https://github.com/NVIDIA/k8s-device-plugin/blob/v0.20.2/cmd/nvidia-device-plugin/main.go)
[Kubernetes Restricted policy](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted)
