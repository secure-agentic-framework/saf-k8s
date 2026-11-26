# SAF-K8S-0701-007 — Storage driver and consumer isolation

From the framework checkout, run the portable case.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0701-007 --docker-context desktop-linux
```

From the lab checkout, invoke `python3 lab.py` with the same arguments.
Kubernetes admits the fixed privileged and hostPath declarations in
server dry-run before Restricted Pod Security enforcement and denies
them afterward. The ordinary nonroot reader mounts its owned PVC
read-only and reads the expected marker. A bounded restricted Pod with
the fixture toleration runs on the exact designated worker. The
otherwise equivalent tenant comparison without the toleration stays
unscheduled. The worker's actual NoSchedule taint is checked separately
from the scheduler's aggregated reason.

## Verify actual storage and exception boundaries

1. Inventory actual block, file, network filesystem and object storage
   paths and versions. Identify controller, node and application
   components and their supported privileges, host mounts, devices and
   confinement. Record what requires elevation and why.
2. Inspect actual Pod Security labels or authorized exemptions and
   workloads able to create or update covered Pods, including indirect
   controller paths. Compare an approved storage installer with an
   ordinary tenant in an authorized dry-run of the actual policy
   boundary. Verify service accounts and permitted locations.
3. Confirm the actual node labels, taints, selectors and tolerations
   match the approved node inventory. Verify controller configuration
   and running Pod placement. Verify separate admission or authorization
   prevents unapproved workloads from opting into reserved placement.
4. Review effective supported AppArmor, SELinux or equivalent host
   controls, and compare a permitted mount or health operation on
   disposable storage. Record limitations, compensating controls and
   exception owners for the installed provider and driver.
5. Verify application access with case-owned marker data. Preserve
   authorized read and denied write outcomes and independent provider
   and storage audit evidence where applicable.

[Kubernetes Pod Security Standards](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-standards/),
[Kubernetes volume and CSI guidance](https://v1-36.docs.kubernetes.io/docs/concepts/storage/volumes/),
and [Kubernetes taints and tolerations](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/).
