# SAF-K8S-0303-007 AppArmor profile readiness

Run `python3 lab.py test SAF-K8S-0303-007` using the catalog revision recorded with
the verified result. The case builds a pinned ARM64 Debian guest image and runs
it in a restricted Kind Job. A read-only, immutable ConfigMap delivers the
exact profile bytes. A disconnected QEMU guest checks the missing profile,
loads the approved profile, confirms an allowed marker and denied canary, and
checks that removing the profile restores the comparison state.

The case publishes a temporary node label after that guest probe and checks
that the scheduler places a benign marker Pod on the selected node. A fresh Pod
cannot schedule after label withdrawal. This label represents the completed
guest probe. Deployment and continuous attestation of AppArmor on actual
eligible nodes, authenticated label ownership, and running-workload response
to readiness loss require environment evidence.

- [Kubernetes AppArmor tutorial](https://v1-36.docs.kubernetes.io/docs/tutorials/security/apparmor/)
- [Linux AppArmor documentation](https://docs.kernel.org/admin-guide/LSM/apparmor.html)
