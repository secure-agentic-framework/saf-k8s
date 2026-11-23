# SAF-K8S-0802-006 Device-plugin mount admission and observability

This case uses the documented Linux kubelet device-plugin path purely as a server-side dry-run Pod declaration. The API denies it when Pod Security Admission is enabled. A scoped metadata-only audit log reports both refused declarations, and an ordinary no-mount CPU Pod runs.

The case never creates a Pod with the mount, opens a socket or runs a device plugin. Host ownership, file modes, host process access, and runtime monitoring still require deployed evidence.
