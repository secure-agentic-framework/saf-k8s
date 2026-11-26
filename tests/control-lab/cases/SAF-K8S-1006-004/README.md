# SAF-K8S-1006-004 automated audit evidence capture

From the SAF-K8S framework checkout, run with local Docker, Kind and kubectl.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1006-004 --docker-context desktop-linux
```

A native CronJob reads named synthetic catalog and crosswalk records and the
Pod Security Admission labels on its own namespace. Its ServiceAccount can
read the expected objects. Actual requests for an unlisted ConfigMap and the
ConfigMap list are forbidden. An independent Pod reads the retained snapshots
from the volume.

The case checks missing, fresh, stale and recovered evidence. After resuming
the collector, both the older snapshot and the new snapshot containing the
revised source record remain readable. Kubernetes exposes the fixture's
Pod Security Admission settings as namespace labels.

The case demonstrates collection and freshness for the fixture. Deployed
coverage, archive retention, external GRC integration and applicability of
crosswalk records require separate evidence.

[Kubernetes v1.36 CronJobs](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/), [Pod Security Admission](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-admission/)

The same test also runs the [scoped API collector](scoped/README.md) against two additional
synthetic namespaces. It checks exact live RoleBindings, NetworkPolicies and Pod Security
labels, verifies source identity and resource versions, and retains the old scheduled
retention checks in the same run.

## Verify the crosswalk readiness projection

The scheduled collection and independent reader remain the native reference.
The synthetic crosswalk importer verifies the exact source bytes and revision,
control and catalog pins, and the named in-source objective. A valid link
produces a ready row. Missing required links and stale source or objective
references produce an attention status and explicit gap codes. Inspect
`crosswalk-readiness.raw.json` for the three reproducible outcomes.

The source and objective are fictional. The projection represents a dashboard
input. Use actual authoritative sources and dashboard consumers when gathering
evidence for an adopting deployment.

1. Record the applicable framework version, exact objectives, reviewed control
   revisions and the owner who approves each relationship.
2. Retain evidence links showing applicability, strength, scope and provision
   of the actual control. Verify each source pin and required relation.
3. In a controlled reporting environment, compare an acceptable input with
   missing and stale links and verify that the actual dashboard and alert
   consumer show the gaps. Record collection time, retention and access scope.
4. Reconcile the inventory and evidence following catalog, deployment or
   framework revisions. Give each unresolved link an owner and review date.
