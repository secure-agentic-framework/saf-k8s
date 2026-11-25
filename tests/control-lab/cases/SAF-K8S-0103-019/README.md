# SAF-K8S-0103-019 Shared API endpoint failover

A disposable Kind cluster has two API servers and Kind v0.32.0 Envoy with HTTPS liveness probes. The case validates both backends, stops only one owned API process without stopping either etcd member, observes authenticated reads through the shared endpoint, and restores the process. The test distinguishes the direct Kubernetes readiness probe from Envoy's HTTPS liveness check on /healthz. The result does not establish application readiness failover, provider availability or production failure-domain independence.

## No eligible backend comparison

The same two owned API servers exercise both single-backend ejection and a
short overlap with neither API process serving. The test requires actual
Envoy health ejection evidence and an unsuccessful authenticated read through
the shared endpoint. Both static manifests are restored through separate
cleanup paths. The test verifies the first restored backend serves authorized
reads before the second returns and both eventually reenter service.

For the assessed endpoint, record approved backend topology and failure
domains, probe route and semantics, ejection and re-entry policy, expected
client retries, shared dependencies and the documented availability target.
In an approved rehearsal, measure representative failures and recovery and
verify the user's normal authenticated API path. Collect the provider service
commitment and any applicable client behavior evidence. Use the measured
local fixture timings only to understand its mechanism.
