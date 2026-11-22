# SAF-K8S-0902-001 — Synthetic inference hardening

Run `python3 lab.py test SAF-K8S-0902-001 --docker-context desktop-linux`.
A nonroot Python fixture serves one inert model marker. A live probe verifies
the exact mounted bytes, immutable mount behavior, the read-only root, and
writable scratch. Disabling the root protection in a replacement Pod makes
the identical root filesystem write succeed. The workload egress policy allows
only the selected local peer on TCP 8080. Both listeners work before policy,
and a separate Pod still reaches the denied destination afterward.

The fixture covers one local Kind CNI and a synthetic inference service.
Production model backends, deployed serving stacks, GPU dependencies,
approved egress inventory, scanning, and patch cadence need separate evidence.

- [Kubernetes Security Context](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Kubernetes NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)
