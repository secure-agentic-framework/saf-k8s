# SAF-K8S-0102-006 — Scheduled API data key rotation

Run the isolated case from the control lab checkout:

```sh
python3 lab.py test SAF-K8S-0102-006 --docker-context desktop-linux
```

The case runs on a digest-pinned Kubernetes v1.36.1 Kind cluster. It configures the API server's Secretbox provider for a dedicated custom resource containing only public fixture markers. The case first reads an older envelope, selects the new writer, rolls back, and resumes rotation while retaining both keys for reads. Real CronJobs then consume separately approved synthetic plans. The not-due Job creates no migration side effects. The due Job rewrites exactly three named records, and the case verifies their new envelopes before removing the old key. After restart it verifies the API and retained records, including re-creating and reading a synthetic recovery marker through the API.

The two CronJobs use a minute cadence and separate service accounts. Each service account can read only its exact named plan and update its own receipt. Only the due account can patch the migration targets. Key material stays in a private temporary fixture configuration. The retained evidence includes the gate decisions, public key labels, and sanitized schedule checks.

The recovery comparison covers an API-level re-create. For durable recovery, verify separately with the provider or storage layer. The companion [KMS v2 integration fixture](../SAF-K8S-0403-020/README.md) covers remote Vault Transit version changes and retained-version recovery in an isolated deployment.

## Adopter verification

1. Record the governed resources, key authority, version, writer and compatible readers, schedule, trigger, approval, change window and rollback owner.
2. Verify the actual trigger and measured writer change on owned representative records. Confirm that prior generations remain readable and that migrated objects use the intended new envelope. Preserve per-scope progress, remaining old dependencies, holds, and failed or unobserved paths.
3. Identify every retained copy, including backup, restore, provider or export paths. Restore the applicable copies in an isolated approved environment and confirm the responsible key versions. Retain approvals, exact successful recovery coverage and the outstanding dependencies before authorizing retirement.
4. Verify observable retirement at the applicable layer, write and read continuity, alerting, and rollback. For remote KMS record provider version identifiers, integration health, effective retention and destroy/disable policy. Keep key material out of retained evidence.

- [Kubernetes v1.36 CronJobs](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/)
- [Kubernetes v1.36 API encryption at rest](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
