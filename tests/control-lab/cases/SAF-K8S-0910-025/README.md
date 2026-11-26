# SAF-K8S-0910-025 reference test: approved endpoint revocation

Run `python3 lab.py test SAF-K8S-0910-025` from the control-lab directory.
The fixture retains its four baseline checks and adds native scheduled
reconciliation after revocation.

The source registry runs in the runner's owned Kind cluster. A separate owned peer has two CNCF Distribution instances. The fixture uses a fixed repository, tag, and deterministic inert image. The original four checks cover ungoverned transfer, governed denial after reset, authorized on-demand drift repair, and approved transfer with independent digest readback. The drift checks verify both observer and manager authorization.

The supplement represents approval as immutable v1/v2 snapshots and a current revision pointer. A separate approval-authority identity selects v2 after the approved destination is emptied; the repair manager cannot move the pointer. The v2 snapshot retains the source and removes the formerly approved destination. A case-owned CronJob runs the same bounded membership reconciler on a one-minute schedule. The case observes one Job with the exact CronJob owner UID and scheduled-timestamp annotation, verifies the active endpoint was removed, attempts the exact fixed transfer, and independently reads the destination manifest and blobs to confirm that nothing new arrived.

This proves one scheduled invocation and one synthetic former-approved endpoint revocation. It does not establish sustained cadence or scheduler reliability, organization change approval, actual external registry identities, retry or alternate replication behavior, or production transport identity. Adopters must verify their real registry identities and egress path, approval/sign-off and version history, a revoked endpoint's effective denial across every replicator and cache, reconciliation schedule/lag/alerting, failure recovery, exceptions, retries, and audit retention. Preserve old immutable snapshots for review according to local retention policy.

- [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md)
- [Kubernetes RBAC resource-name restrictions](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-resources)
- [NIST OSCAL Content v1.5.0 / SP 800-53 Rev. 5.2.0](https://github.com/usnistgov/oscal-content/releases/tag/v1.5.0)
- [Kubernetes v1.36 CronJob scheduling](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/#job-creation)
