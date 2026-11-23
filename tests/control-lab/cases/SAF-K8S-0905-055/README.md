# SAF-K8S-0905-055 — Validate declared model source references

Run the case by ID from the framework checkout.

    python3 tests/control-lab/lab.py test SAF-K8S-0905-055 --docker-context desktop-linux

Three native policies check the same declared source fields at the Pod, ordinary workload template, and CronJob template paths. A named ConfigMap supplies exact approved HTTPS and OCI values. The case exercises six workload kinds, init containers, an update to a persisted zero-replica Deployment, rotation of a source URL, and fail-closed behavior after parameter deletion. Inputs are inert and source strings are never contacted.

Verify production namespace enrollment, parameter ownership, other application source lookup paths, and egress separately.

- [Kubernetes 1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes 1.36 CEL](https://v1-36.docs.kubernetes.io/docs/reference/using-api/cel/)
