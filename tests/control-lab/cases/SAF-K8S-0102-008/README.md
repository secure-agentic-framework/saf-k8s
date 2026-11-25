# SAF-K8S-0102-008 — Fixture-reference etcd snapshot comparison and restore

```sh
python3 lab.py test SAF-K8S-0102-008
```

The case opens one synthetic Kubernetes v1.36.1 kind cluster and takes an
etcd snapshot containing a public ConfigMap marker. This scratch revision keeps
the captured source under `capture/`, a same-run fixture SHA-256 reference under
`trust/`, the candidate under a distinct `staging/`, and the recovered
database at the isolated `/restore/store` path. The local reference is a synthetic test
oracle; it does not prove production manifest authenticity or key custody.

The source digest and native snapshot metadata are checked before promotion.
Under the case's sequential single-writer assumption, one helper exclusively
creates a mode-0600 `.part` file, copies and rechecks its bytes, then uses a
same-directory atomic rename to `staging/verified.db`. A truncated artifact
and a second valid snapshot taken after a marker change go through that helper
and leave staging empty. They are also sent
through the existing restore gate; neither enters native restore.

The intact staged artifact is verified again and restored with native hash
checking, a revision bump, and compaction. The recovery container uses
Docker network mode `none`. The test reads only the exact synthetic
ConfigMap record and confirms that the old revision is compacted. Artifact
contents and keys stay out of test evidence.

The fixture reference and recovery artifacts live in a private temporary
directory. The expected digest is generated from the captured source during
this same run as the fixture’s comparison reference.
Production provenance depends on protection of the expected digest or
validation of a trusted signature. Backup custody, managed export
compatibility, and Kubernetes controller recovery remain separate deployment
checks.

- [etcd v3.6 disaster recovery](https://etcd.io/docs/v3.6/op-guide/recovery/)
- [Kubernetes v1.36 operating etcd](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/configure-upgrade-etcd/)

The case compares the exact restored synthetic value bytes with the value
captured before the snapshot. Both refused artifacts and the accepted artifact
use the same fixture-reference comparison. The rejected paths record zero staging promotions
and zero restore calls; the accepted path records one of each. The seven
existing receipt checks remain seven: two red candidate refusals, pre-promotion
source validation, post-promotion verification, the original restore value
and revision checks, and the exact restore-call gate.

## Adopter evidence: backup custody and recovery

For each production cluster and each managed-service export path, inventory the snapshot source, schedule, covered cluster state, encryption and staging destinations, retention, signer or digest-manifest owner, and restore owner. Obtain the provider's supported backup/export format and restore procedure; do not infer customer-verifiable etcd snapshots from platform-managed control planes.

Demonstrate the trust path from snapshot creation through storage and restore: identify which independent principal protects the expected digest or signing key, where verification occurs before storage and again before restore, and how unauthorized changes to both an artifact and an unsigned checksum are prevented. Record permissions and separation between the backup writer, manifest/signing identity, storage administrator, and restore operator. Keep key material, digest values, snapshot bytes, credentials, and sensitive keyspace data out of the evidence packet.

Rehearse a representative restore in an approved isolated recovery environment using the provider-supported workflow. Preserve version/provenance, backup identifier, integrity-verification result, exact synthetic or approved sentinel state, revision bump/compaction behavior where Kubernetes watchers apply, control-plane readiness, API health, controller convergence, and cleanup evidence. Include recovery point and recovery time measurements, and document gaps where a provider does not expose the underlying snapshot or verification interface. This adopter evidence is distinct from the case's synthetic Kind proof and requires authorization for the target environment.
