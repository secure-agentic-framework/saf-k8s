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

## Identity-based toleration admission supplement

The additive identity_toleration_supplement.py creates a case-owned namespace,
two ServiceAccounts, and matching namespaced Roles/RoleBindings that grant
both principals only pods/create. A native Kubernetes ValidatingAdmissionPolicy
and Binding apply to Pods in that fixture namespace. The policy permits the
reserved storage toleration only when the API request principal is the exact
storage-installer ServiceAccount identity.

Using the same harmless, restricted, tokenless Pod shape and same toleration,
the approved identity creates one bounded Pod that reaches Succeeded on the
case-owned tainted worker. The tenant identity's otherwise-authorized server
dry-run is rejected with the policy-specific denial, and the attempted Pod is
independently confirmed absent. The fixture does not add a privileged Pod,
hostPath, actual storage driver, or provider exception. It does not prove
production identity governance, access to modify policy, or the deployed
provider's host behavior. The policy, binding, namespace, and service accounts
are deleted during cleanup; the parent case removes the worker taint and label.
The case now has eight assertions, retaining the original seven.

Kubernetes documents ValidatingAdmissionPolicy as stable since v1.30 and
requires a matching Binding for a policy to take effect. Its v1.36 taint
guidance explains that tolerations permit scheduling but do not guarantee
placement, and identifies admission as the mechanism for restricting which
users may use dedicated nodes:
https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/
https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
