# SAF-K8S-0303-007 AppArmor profile readiness

Run `python3 lab.py test SAF-K8S-0303-007` using the catalog revision recorded with
the verified result. The case builds a pinned ARM64 Debian guest image and runs
it in a restricted Kind Job. A read-only, immutable ConfigMap delivers the
exact profile bytes. A disconnected QEMU guest checks the missing profile,
loads the approved profile, confirms an allowed marker and denied canary, and
checks that removing the profile restores the comparison state.

A fixture ServiceAccount can publish or withdraw readiness on one named node.
A read-only ServiceAccount and the kubelet identity are denied changes to the
protected label. The scheduler leaves the marker unscheduled when readiness
is missing, stale or withdrawn and starts it with the current profile digest.
Withdrawing readiness leaves an existing Pod running until explicit deletion.
A separate Pod requests an unavailable `Localhost` profile. The test requires
a scheduled Pod, an AppArmor startup error and absence of the workload marker.

## Coverage boundary and adopter checks

The QEMU guest has no network device and receives only the immutable ConfigMap
fixture. It uses a separate kernel from the Kubernetes node. The test verifies
guest enforcement, native scheduling, authorization for the fixture publisher
and native startup rejection of an unavailable profile. Positive enforcement
of the approved profile on a workload node still requires a compatible node
with the actual profile loaded and bound to the workload.

For adoption, verify each eligible node's kernel and CRI support, loaded profile
name and revision in enforce mode, and a harmless denial from a workload using
that profile. Verify a policy controller or provisioning identity owns and
updates readiness; RBAC must prevent ordinary users and workloads from writing
or changing the protected node label. Confirm Node authorization and the
NodeRestriction admission plugin are active if relying on the
`*.node-restriction.kubernetes.io` label namespace. A protected label only
blocks kubelet identities from changing it; it does not authenticate the
administrator/controller that writes it. Enforce required per-container
`Localhost` profiles at admission so omission or override cannot bypass the
gate. Finally, test missing, wrong-revision and withdrawn readiness against
fresh Pods and existing Pods separately, and verify the chosen drain, delete,
restart, or quarantine response and its owner. Node labels affect scheduling
of new Pods; they do not evict or stop already-running Pods.

- [Kubernetes AppArmor tutorial](https://v1-36.docs.kubernetes.io/docs/tutorials/security/apparmor/)
- [Linux AppArmor documentation](https://docs.kernel.org/admin-guide/LSM/apparmor.html)
