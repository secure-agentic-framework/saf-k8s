# SAF-K8S-0301-001 — Pod Security Standards level assignment

This case uses two synthetic namespaces. `saf-0301-restricted` is assigned
Pod Security Admission (PSA) `restricted` at pinned version `v1.36` for
enforce, audit, and warn. `saf-0301-baseline` is separately assigned `baseline`
at `v1.36`; its namespace annotation records why this comparison exception
exists. Neither namespace represents a production namespace or a system
workload.

The first harmless Pod manifest omits only the Restricted-required container
security-context fields `allowPrivilegeEscalation: false` and
`capabilities.drop: [ALL]`. The case submits that identical manifest to the
server using dry-run while the Restricted namespace is temporarily Baseline,
then assigns Restricted and repeats the dry-run. PSA should accept the first
request and reject the second for a Restricted-specific reason. It also checks
that the separate documented Baseline namespace still accepts the dry-run.

The restricted probe is never persisted or launched. The sole created workload
is a harmless BusyBox Pod with the required Restricted security context; the
case waits for it to become Ready. All image references come from the existing
digest-pinned shared fixture. This case definition does not itself assert that
any cluster was run; any runtime result must be retained separately as lab
evidence.
