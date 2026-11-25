# SAF-K8S-0802-006 Device-plugin mount admission and observability

This case uses the documented Linux kubelet device-plugin path purely as a server-side dry-run Pod declaration. The API denies it when Pod Security Admission is enabled. A scoped metadata-only audit log reports both refused declarations, and an ordinary no-mount CPU Pod runs.

The case never creates a Pod with the mount, opens a socket or runs a device plugin. Host ownership, file modes, host process access, and runtime monitoring still require deployed evidence.

## Adopter verification

1. Inventory actual device-plugin manifests, mounts, runtime profile, writable host paths and namespace or admission exemptions. Document ownership and the purpose, scope and access mode of each approved mount.
2. Check the running plugin spec and effective mount and filesystem access on representative owned nodes. Verify only approved paths and operations succeed, and use bounded dry-run requests to confirm denied declarations and attributable audit decisions.
3. Retain plugin version, platform policy, effective mount evidence and reviewed exceptions. Recheck after node image, plugin, policy or plugin namespace changes.
