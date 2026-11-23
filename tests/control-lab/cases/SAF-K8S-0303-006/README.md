# SAF-K8S-0303-006 AppArmor profile refinement

Run `python3 lab.py test SAF-K8S-0303-006` using the catalog revision recorded in
the verified result. A restricted Kind Job uses an isolated AppArmor guest.
Two ordinary cycles have no corresponding policy exception. The guest then
exercises a separate recovery path, confirms the targeted would-be denial in
complain mode, and observes that enforcing the original policy blocks it.

The exact revised profile permits the approved recovery and ordinary operations
while continuing to reject an excluded canary. The case verifies both approved
profile digests and removes the fixture profile. Production promotion still
depends on workload-specific path coverage, event collection, approval and
rollback, especially when runtime or workload changes.

- [AppArmor profile modes](https://apparmor.dev/man/apparmor.d/)
