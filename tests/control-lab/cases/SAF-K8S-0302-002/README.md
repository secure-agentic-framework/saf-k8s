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
