# SAF-K8S-0704-013 — Kubernetes and managed-provider audit collection

From the framework checkout, run the disposable audit-delivery test.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0704-013 --docker-context desktop-linux
```

From the lab checkout, invoke `python3 lab.py` with the same arguments.
The Kind API server records Metadata-level patches to one fixture
ConfigMap. A collector reads that exact log file through a read-only
mount, separately accepts a labeled synthetic provider record, and
delivers only enrolled sources to an independent in-cluster receiver.
Enrolling the API source delivers its actual audit identity and event
fields. During a receiver outage the collector keeps a pending record.
After the receiver is recreated, an independent client reads the old
records and the retried event exactly once from the PVC-backed receiver.

The collector runs as UID 0 to read the one fixture log on its owned
Kind node, with all capabilities dropped, no service account token, a
read-only root filesystem, and no privilege escalation. Transport uses
local HTTP inside the disposable cluster. The provider record is
synthetic. The fixture covers the one API category and receiver restart.

## Verify managed Kubernetes and cloud delivery

1. Inventory actual Kubernetes and cloud producers across the governed
   clusters, accounts, and regions. Record enabled and excluded
   categories and the authority that owns each collector configuration.
   Compare mandatory coverage against the adopted framework scope.
2. In the authorized staging path, emit a benign governed action from
   each actual source. Compare source request or event ID, time,
   category, actor and target with the authenticated collector's
   observation and an independent destination query. Establish
   explicit lag, completeness and duplication acceptance criteria.
3. Verify authorization and authenticated transport at every hop, least
   privilege of the collector and reader, and the handling of sensitive
   event fields. Compare an expected delivery with a representative
   denied or unenrolled route.
4. Exercise an approved receiver interruption, confirm delivery failure
   is observable, and verify retry and destination readback against the
   exact distinct source IDs. Check loss handling and retention at the
   adopted destination independently of local collector state. Preserve
   receipts with source, cluster, account, event category and timestamps.

[Kubernetes v1.36 audit logging](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
and [Kubernetes v1.36 hostPath volumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/volumes/#hostpath).
