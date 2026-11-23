# SAF-K8S-0905-053 — Revalidate the model source allowlist on a schedule

Run the case by ID from the framework checkout.

    python3 tests/control-lab/lab.py test SAF-K8S-0905-053 --docker-context desktop-linux

A suspended CronJob leaves old entries untouched. Once enabled, two real controller-owned Jobs run one minute apart. The first applies the fixture review, keeping one source, updating one renamed source, and removing the stale and revoked sources. The allowlist and its decision history change in the same Kubernetes API update. The second Job observes the completed cycle and leaves policy and history intact. Its ServiceAccount has read-only access to the immutable review input.

The accelerated schedule demonstrates controller behavior on Kind. The intended organizational review cadence, enabled source approvals and long-term audit history require deployed evidence.

- [Kubernetes 1.36 CronJob](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/)
- [Kubernetes 1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
