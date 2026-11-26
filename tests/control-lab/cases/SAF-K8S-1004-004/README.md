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
