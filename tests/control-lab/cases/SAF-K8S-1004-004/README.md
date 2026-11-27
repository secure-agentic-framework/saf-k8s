# SAF-K8S-1004-004

The native Kubernetes Job loads offline synthetic advisory bytes and synthetic observations.
A missing SHA-256 pin, altered bytes and an expired pinned bundle each produce quarantine
with no enrichment. A current pinned bundle enriches one exact image, package and version
match. The different image and version observations produce no match. The lab retains the
Job's full result and the individual assertions. A fixed evaluation date makes the outcomes
reproducible.

The Kubernetes Security Response Committee publishes official disclosures as JSON and RSS.
NIST NVD maintains CVE/CPE APIs and JSON feeds. NVIDIA PSIRT publishes product bulletins.
The bundled fixture deliberately uses invented identifiers and a small local schema.
Production subscriptions, source trust, update scheduling, runtime sources, deployed SIEM
detection changes and exposure handling require separate evidence.

- [Kubernetes official CVE feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/)
- [NIST NVD data feeds](https://nvd.nist.gov/vuln/data-feeds)
- [NVIDIA Product Security](https://www.nvidia.com/en-us/security/)

For a deployment, identify the actual approved feed endpoints and owner, provenance and trust, refresh interval and failure behavior. Independently connect a real advisory to the exact governed component version and observed asset, and retain the approved exposure decision or downstream rule revision. Keep actual source-level coverage and privacy constraints with deployment evidence.

The same evaluator also consumes approved and changed public fixture bytes from an owned ClusterIP HTTPS service. The runner generates a short-lived local CA and serving key outside the case tree. The independent client validates the expected hostname and pinned CA, rejects an unrelated CA, and applies the same byte-integrity, expiry and enrichment decisions.

## Official Kubernetes feed

A separate tokenless Job in the disposable cluster reads the Kubernetes
Security Response Committee’s official JSON endpoint over HTTPS. It verifies
the certificate and hostname using the image’s trust store. The parser checks
the feed identity and schema, requires unique CVE identifiers, and validates
the ordering of publication, source-update and retrieval timestamps. It
retains the response and metadata digests, timestamp evidence and a count.
The Job never follows item URLs or retains advisory text.

This bounded read demonstrates one public source and one live retrieval.
The existing fixture continues to demonstrate quarantine and enrichment.
Verify the deployed source inventory, subscription cadence, delivery and
analyst workflow using evidence from the adopter’s environment.

## Bounded local recovery counterfactual

The recovery check uses the case-owned HTTPS server and a fixed synthetic
bundle. Its `/recover` route returns one empty authenticated 503 with
`Retry-After: 1`, then serves the same approved pinned bytes on the next request.
The worker confirms the first response produces `source_unavailable` with zero
enrichment, waits the supplied one second, retries once, and requires the second
response to yield exactly the existing synthetic match. It records only bounded
status, retry, byte-count, digest and evaluator fields. This tests one local
recovery path; the one-second fixture interval is not a production polling or
backoff recommendation and makes no claim about a deployed subscriber.

[Official Kubernetes CVE feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/)

## Synthetic source availability counterfactual

The case uses a temporary, scoped bearer credential against two local
HTTPS routes. The
authenticated `/ready` route returns the same approved synthetic bundle, while the
authenticated `/unavailable` route returns an empty 503 with `Retry-After: 30`; an
unauthenticated request receives an empty 401. Both authenticated responses go through
the same response evaluator: the healthy route must produce the existing single exact
synthetic enrichment, while the 503 must produce none. The credential is generated per run, mounted from a
temporary Secret, and excluded from command logs and worker output. The worker records
only statuses, empty-body lengths, retry metadata and a bounded evaluator disposition.
It must report `source_unavailable` with no enrichment. The original seven checks are
unchanged.

This does not infer staleness from the publication date of any real CVE. Retrieval
availability and the age of the latest advisory are separate properties; any maximum
source age, polling cadence, alternate-source policy and operational notification need
adopter-defined values and deployment evidence. No production subscriber behavior is
claimed.
