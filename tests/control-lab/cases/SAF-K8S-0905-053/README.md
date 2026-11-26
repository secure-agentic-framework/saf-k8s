# SAF-K8S-0905-053 — Revalidate the model source allowlist on a schedule

Run the case by ID from the framework checkout.

    python3 tests/control-lab/lab.py test SAF-K8S-0905-053 --docker-context desktop-linux

A suspended CronJob leaves old entries untouched. Once enabled, two real controller-owned Jobs run one minute apart. The first applies the fixture review, keeping one source, updating one renamed source, and removing the stale and revoked sources. The allowlist and its decision history change in the same Kubernetes API update. The second Job observes the completed cycle and leaves policy and history intact. Its ServiceAccount has read-only access to the immutable review input.

The accelerated schedule demonstrates controller behavior on Kind. The intended organizational review cadence, enabled source approvals and long-term audit history require deployed evidence.

- [Kubernetes 1.36 CronJob](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/)
- [Kubernetes 1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)

## Adopter verification

1. Export the authoritative allowlist with stable source IDs, canonical repository/registry namespace, publisher identity, source owner, applicable AI systems and every consuming pipeline or admission/deployment decision point. Reconcile it to the organization's complete external-model-source inventory.
2. Show the review criteria and cadence, including event-triggered reassessment for publisher, repository, ownership, trust, license or security changes. Preserve source evidence and the exact version evaluated. Identify the authenticated human reviewer and approver, their authority, and required separation; retain approvals and reasons.
3. Demonstrate one approved entry remains available, one renamed source is updated by an approved decision, one revoked source is removed/blocked, and one stale source is retired. Verify the resulting policy and decision record are tied to the same review revision and timestamp.
4. Verify the deployed CronJob/controller identity, schedule, RBAC, failure/late-run alerts, retry behavior and protected audit/history retention. Confirm only authorized reviewers can modify the approval input and only the bounded worker can apply approved decisions.
5. Trace policy propagation to every actual consumer. Verify an approved fixture or harmless source is accepted and revoked/unlisted sources are rejected at each consumer; record any asynchronous propagation delay, failures and reconciliation owner. The portable case changes a ConfigMap and does not prove consumer rollout or enforcement.
6. Preserve the source snapshot, review evidence, human decision, resulting allowlist/history version, controller/job result, consumer observations, exception and follow-up. Repeat on the defined cadence and after material trust changes.
