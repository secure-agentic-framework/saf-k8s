# SAF-K8S-0104-018 Kubernetes security advisory and provider bulletin monitoring

```sh
python3 lab.py test SAF-K8S-0104-018 --docker-context desktop-linux
```

The [catalog control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0104-018.md)
requires active monitoring of Kubernetes, CVE and relevant provider and
dependency advisory sources. The upstream Kubernetes feed may lag a disclosure
and covers official Kubernetes advisories. Provider programs have their own
coverage and delivery details. Configure sources to match the deployed
inventory.

This case serves an inert Kubernetes JSON Feed 1.1 record and an RSS 2.0
provider record inside kind. The Kubernetes record uses the native CVE ID field
with a synthetic identifier. The CronJob controller schedules polling every
minute. While the upstream endpoint returns HTTP 503, a scheduled Job records
that source failure and still parses the available RSS feed. A later Job from
the same CronJob parses both sources after the fixture recovers. Job ownership
and scheduled timestamps must match the CronJob.

This example verifies the scheduled monitoring path against inert sources.
Production evidence is required for subscription freshness, coverage across
the cluster and dependency inventory, notification delivery and response.

- [Kubernetes official CVE feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/)
- [Kubernetes JSON feed field definitions as published](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json)
- [AWS Security Bulletins](https://aws.amazon.com/security/security-bulletins/)
- [GKE cluster notifications](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/cluster-notifications)
- [Go release history and security fixes](https://go.dev/doc/devel/release)
- [Go Vulnerability Database and OSV schema](https://go.dev/doc/security/vuln/database)
- [GO-2026-6851: Go toolchain `cmd/go` and `cmd/link`](https://pkg.go.dev/vuln/GO-2026-6851)
- [GO-2026-6859: Go standard library `net/http`](https://pkg.go.dev/vuln/GO-2026-6859)

The poller sends the inert records and source failure to a separate, named
fixture recipient. The recipient's ledger persists across polling Jobs and
the feed-server rollout. Its receipt confirms delivery, and repeated reads
of the provider item yield one stored notification. The ledger stays in the
disposable receiver Pod's volume for the rehearsal.

## Verify your implementation

1. Inventory Kubernetes distributions, node runtimes, ingress, CNI, CSI,
   add-ons and provider services. Map each to an authoritative maintained
   advisory source, expected polling interval or subscription, assigned
   recipient and backup route. Record coverage for each cluster and version.
   For Go-built in-scope components and their build systems, also monitor the
   Go release/security channel and Go Vulnerability Database. Track each GO
   advisory ID and CVE alias, affected module (`toolchain` or `stdlib`),
   affected Go version range, source revision/retrieval time, supported-release
   status and owner. Keep builder-toolchain advisories distinct from
   standard-library findings in deployed binaries.
2. Record the last successful collection, expected cadence and evidence
   that feed access or subscription authorization still works. Test a
   representative outage and recovery. Verify health errors reach the
   owner while unaffected sources continue. Account for publication lag
   and quiet periods separately from collection failures.
3. Exercise a benign test advisory and record successful ingestion, routing,
   recipient receipt and handoff for triage. Test duplicates and revised
   advisories. Retain the source identity, authoritative advisory ID and
   revision, collection and delivery times, recipient, escalation and
   operator evidence as applicable. Keep raw advisory contents within the
   intended review system.
4. Use these records as evidence for the covered portions of NIST SI-5,
   SI-5(1) and SSDF RV.1.1. Document the internal alert and directive
   workflow, organization-wide delivery where required and investigation of
   credible reports in their own process records.

- [NIST SP 800-53 Rev. 5, release 5.2.0](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST SSDF v1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
