# SAF-K8S-0301-002 Pod Security Admission version pinning

This case checks that a namespace admission rule requires explicit supported
enforce, audit, and warn versions on CREATE and UPDATE. The known production
and staging fixture names fall under the rule even without the governance
label. A separately classified namespace outside the fixture scope is allowed.
Pinned levels include each level the platform supports. The test runs a benign
Pod and uses harmless dry-run requests to inspect denial, warning and an
independent API audit annotation for the same Restricted policy version.

```sh
python3 lab.py test SAF-K8S-0301-002 --docker-context desktop-linux
```

## Verify in an adopter's environment

1. Start from the full production and staging namespace inventory and approved
   ownership, rather than selecting only already labeled namespaces. Compare
   the inventory with platform and GitOps state and examine approval for
   explicit native exemptions. Verify that authorization restricts namespace
   creation, policy label changes and exemption changes.
2. Check the selected PSS profile and explicit supported minor pin for each
   mode. Reject missing, floating, unsupported and unauthorized changes in
   the declarative pipeline and active API. Verify a benign compliant Pod,
   a safe expected deny, the warning, and the audit backend event with the
   relevant mode and version. Collect only authorized event metadata.
3. Recheck namespace inventory, bindings, policy versions and all three
   observations before and after a platform or provider upgrade. Record
   actual release versions, approvals, label snapshots, exact outcome and
   event IDs. Treat gaps in provider change timing or log access as unverified.
   Check exemption ownership and alternate enforcement separately.

The Kind proof covers one v1.36.1 API server. Other platform releases, provider
upgrade events, and actual production/staging completeness need adopter evidence.

- [Kubernetes v1.36 Pod Security Admission](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Kubernetes v1.36 namespace labels](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/enforce-standards-namespace-labels/)
- [Kubernetes v1.36 API auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
