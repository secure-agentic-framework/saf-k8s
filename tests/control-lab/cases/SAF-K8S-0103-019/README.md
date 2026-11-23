# SAF-K8S-0103-019 Shared API endpoint failover

A disposable Kind cluster has two API servers and Kind v0.32.0 Envoy with HTTPS liveness probes. The case validates both backends, stops only one owned API process without stopping either etcd member, observes authenticated reads through the shared endpoint, and restores the process. The test distinguishes the direct Kubernetes readiness probe from Envoy's HTTPS liveness check on /healthz. The result does not establish application readiness failover, provider availability or production failure-domain independence.
