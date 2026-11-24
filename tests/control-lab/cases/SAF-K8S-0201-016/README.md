# SAF-K8S-0201-016 Node audit forwarding and centralized reviewability

From the framework root, run:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0201-016 --docker-context desktop-linux
```

The case uses a two-node Kubernetes v1.36.1 Kind cluster and the native Linux
Audit guest fixture from [SAF-K8S-0201-015](../SAF-K8S-0201-015/README.md).
It imports a selected native read event as a sanitized marker with a
fixture-specific source and kernel audit serial. The sender verifies the
receiver CA and DNS identity, and the receiver verifies and records the
sender's certificate identity using separate fixture credentials.

The receiver rejects an uncredentialed connection and returns 503 to the
authenticated sender during the outage. The test recreates the sender with
the original bound spool and removes the initial source before it resumes.
Restoring receiver acceptance delivers the marker, drains the spool after
acknowledgement, and makes a verified query possible. The central transaction
commits before acknowledgement. The same receiver volume retains the event
through Pod replacement, and a repeated delivery leaves exactly one record.

The case separately preserves the earlier receiver example and its two-node
canaries. A controller-scheduled check detects missing node markers, then
two later executions retrieve the retained markers from both fixture nodes.

## Verify your implementation

- Inventory each audit producer, its rule coverage, effective local retention,
  transport and central destination. Exercise approved marker events for
  each node class and verify their source identity and queryability. Select
  representative staging for actual ingest or tail behavior, file rotation
  and node or agent restart.
- Verify protected transport and scoped identities, including CA and endpoint
  verification, client authentication where applicable, and failure behavior.
  Record approved policy, key management and attributable evidence without
  collecting private credentials or file contents.
- Check acknowledgement, replay, durable sender state, loss and queue
  pressure during bounded outages. Verify retention and recovery at both
  the source and sink. Test the configured retention period and approved
  hold or deletion policy with attributable records.
- Compare expected node inventory with observed sources on a schedule.
  Rehearse a missing-source finding, retrieval, alert delivery and response.
  Retain the schedule, query, event identifier, demonstrated alert and owner.
  Record unsupported scope or dated service-specific provider evidence.

- [Linux Audit upstream forwarding plugin](https://github.com/linux-audit/audit-userspace/blob/v4.2.1/audisp/plugins/remote/audisp-remote.c)
- [Kubernetes v1.36 PersistentVolumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/persistent-volumes/)
- [Kubernetes v1.36 CronJobs](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/)
