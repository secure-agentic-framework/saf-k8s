# SAF-K8S-0102-022 Backup repository least-privilege access

A disposable Kind Pod tests Linux filesystem authorization with three distinct non-root identities and a shared repository fixture. It verifies baseline access, denied unrelated access, read-only restore access and the intended writer. The file holds a public marker. This checks a native filesystem boundary under Kubernetes. Actual backup copies, remote storage policy, host and cluster administrators, key custody and exceptional access still require deployment evidence.

## Adopter verification

1. Inventory every snapshot and restore-media copy from creation through
   staging, exports, versions, retention tiers, offline media and restoration.
   Record destination, owner, configured identity and encryption key ID.
2. Inspect effective repository permissions for each principal, including
   inherited access, ACLs, alternate paths, service trust and provider access.
   Check read, list, create, update, delete, retention and restore individually.
3. Use an approved authorization simulation or synthetic marker destination.
   Verify the backup writer can use only the intended prefix, the approved
   restore identity can retrieve without modification, and the unrelated
   identity cannot list, read or write. Verify exceptional access through the
   approved scoped path and compare against [SAF-K8S-0102-023](../SAF-K8S-0102-023/README.md).
4. Review key access as its own authorization path. Record custodians, inherited
   grants, approval, relevant events and the supported recovery exercise.
   Retain policy versions, sanitized request IDs, decision summaries, scope,
   exceptions and approval. Keep credentials and backup contents outside evidence.
