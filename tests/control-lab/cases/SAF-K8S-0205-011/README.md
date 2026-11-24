# SAF-K8S-0205-011 Firewall change reconciliation

The test changes only a detached ruleset table on an owned Kind node. A
separate read-only comparison checks the initial approval, two timed drift
samples, a syntax check and preview, the approved change and rollback. The
comparison preserves rule content and order and excludes only assigned
handles and counter totals. The case proves a counter-only change compares
equal while a real TCP selector change produces drift with the comment
unchanged.

An authorized fixture actor creates immutable approval records. A read-only
fixture observer obtains the records and cannot create a replacement. The
API server independently logs both identities, their decisions and times.
The fixture has no packet hook and tests the audit workflow for a single
ruleset plane.

```sh
python3 lab.py test SAF-K8S-0205-011 --docker-context desktop-linux
```

## Verify an adopter's firewall audit process

1. Inventory host, provider, CNI and other governed firewall planes. Record
   the unique target, effective-state source, approval authority, collection
   identity, expected cadence, evidence protection and exception owner.
2. Review the approved baseline artifact and authenticate its approval
   and change identifier. Collect effective rules using read-only access or
   an approved platform export. Record tool version, target, collection time
   and snapshot digest. Preserve rule order, policies, bound interfaces,
   hooks, sets and semantic fields. Exclude handles and volatile counters
   only when they have no decision significance for the governed plane.
3. Compare effective to approved and distinguish drift from missing, partial
   or stale collection. Check actual job completion records against required
   cadence and verify a new sample follows each change. In equivalent
   staging, verify a counter-only difference, controlled drift, an authorized
   change with separate approval provenance and rollback against its baseline.
4. Enforce and retain exception owner, scope, reason, expiry, resolution,
   before/after state and audit record. Track unavailable provider state by
   owner. Leave incomplete planes unresolved until observations are available.

- [Kubernetes audit events](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [nftables reference manual](https://netfilter.org/projects/nftables/manpage.html)
