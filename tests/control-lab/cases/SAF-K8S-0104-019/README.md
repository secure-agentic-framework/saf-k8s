# SAF-K8S-0104-019 Kubernetes CVE risk prioritization

```sh
python3 lab.py test SAF-K8S-0104-019 --docker-context desktop-linux
```

The [catalog control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0104-019.md)
requires severity, exploitability, exposure, and cluster-specific impact to
inform a documented vulnerability-triage workflow. The fixture uses only
invented advisory identifiers, inert records and synthetic inventory.

This case runs two Kubernetes Jobs over identical records. Ordering by CVSS
base score alone places a higher-severity unexposed record first. The example
contextual policy ranks an exposed KEV-listed fixture first and keeps the
applicable version interval in the finding. Both Jobs exclude the component
whose version is at the interval's exclusive upper bound.

The sample accepts only simple, nonnegated CPE OR nodes with an inclusive
start and exclusive end. A production implementation needs the deployed
inventory and provider patch context, the actual data sources and applicability
rules, and evidence of triage, accountabilities, and timing. The fixture scores
and rankings define the example policy.

- [Kubernetes official CVE feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/)
- [NVD API vulnerability and applicability fields](https://nvd.nist.gov/developers/vulnerabilities)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document)

## Version-scoped evidence and follow-up

Catalog revision `7e2e05c327f54bcc2c6aefd64c255880a81ce7c9` adds a second pair of Jobs.
It compares generic advisory summaries with a policy that checks exact build
identifiers. An exact provider record clears a synthetic backported build,
while two contradictory records and an unknown build stay open with an owner
and review deadline. An affected fixture preserves its inference impact and
response deadline. The policy's deadline and source records are invented.

A third Job pair evaluates exact distribution, component and build identity,
reviewed source authority, freshness, dated exposure evidence, and deadline
behavior. Wrong-issuer and stale evidence keep synthetic records open.
The same affected record is evaluated before and after its due time. The
late run retains the original deadline and owner and records escalation.
Both evaluations use simulated checkpoints and inert records.

## Verify your implementation

1. Retain a dated scoped inventory with opaque cluster and asset IDs,
   exact installed builds, distribution and ownership, coverage and exclusions.
   Record the applicable authoritative advisory ID, issuer, revision, source
   retrieval time and protected digest or immutable evidence reference. For
   each Go-built component, bind the deployed OCI image digest and executable
   SHA-256 to the embedded Go version from `go version -m` on that exact
   executable. Corroborate embedded build metadata, distributor builds and
   any backports with verified provenance or a version-specific vendor
   advisory. Verify the
   provenance subject digest and trusted signer/builder identity, and retain
   the Go toolchain input/version. If provenance omits the toolchain or cannot
   be verified against the deployed digest, leave applicability unresolved.
2. Match the affected component and build to the applicable source. For Go
   advisories, distinguish `toolchain` findings (for example `cmd/go` and
   `cmd/link`, which concern the build environment) from `stdlib` findings
   linked into deployed executables. Match each GO ID to its affected module,
   version range and relevant component/build. Keep conflicting, stale and
   missing applicability evidence open with a named owner and a review
   deadline. Apply that review to unsupported toolchains, missing provenance
   and conflicting backport evidence. Record the source and evidence that
   support any closure. Mark exposure unknown when the attributable
   observation is missing or stale.
3. Apply the approved risk policy. Retain severity and exploitation-status
   inputs, measured exposure, workload and tenant impact, policy version,
   owner, trigger timestamp and due time. Keep original deadlines and
   record acknowledgement, escalation, mitigation and verification times.
4. Review a sample of applicable, resolved, conflicting and overdue cases.
   Confirm that responsible reviewers can trace each disposition to the
   exact evidence and that elapsed-time or escalated states are represented
   accurately. Preserve the evidence bundle and the workflow decision.

- [NIST SSDF v1.1, RV.2.1](https://csrc.nist.gov/pubs/sp/800/218/final)
- [Go `go version -m` binary build metadata](https://go.dev/ref/mod#go-version-m)
- [SLSA Build Provenance specification](https://slsa.dev/spec/v1.1/provenance)
- [Go release history and supported-release policy](https://go.dev/doc/devel/release)
- [Go Vulnerability Database and OSV schema](https://go.dev/doc/security/vuln/database)
- [GO-2026-6851: Go toolchain `cmd/go` and `cmd/link`](https://pkg.go.dev/vuln/GO-2026-6851)
- [GO-2026-6859: Go standard library `net/http`](https://pkg.go.dev/vuln/GO-2026-6859)
