# SAF-K8S-1007-007 Metrics companion candidate

The case retains the 11 admission, priority and health checks and adds three checks with a TLS-verified Metrics Server. Run `python3 tests/control-lab/lab.py test SAF-K8S-1007-007 --docker-context desktop-linux` from the framework checkout. This normal test command builds a temporary Kind profile for the owned cluster.

## Added observations

- Reuse the 1002-005 Metrics Server v0.8.1 manifest digest and image digest. The case creates temporary kubelet and APIService certificates, configures the single owned Kind control-plane kubelet to serve the fixture certificate, and verifies the APIService CA bundle and service identity. TLS verification remains enabled for kubelet and aggregation.
- Read the actual `metrics.k8s.io/v1beta1` PodMetrics object for `saf-test/saf-1007-007-shared-health` before and after the existing quota probes. Each sample must have CPU and memory usage, be no older than 90 seconds, and be bracketed by Pod API reads with the same UID as the original fixture Pod. Raw metrics responses and resource quantities are not retained.
- Read at most the last 100 lines from that Pod's `mock-workload` container before and after. The check stores only whether fixed `/healthz` HTTP 200 entries were present and whether their count increased. It does not retain log text.

The three added checks are one trusted APIService setup check from the reused helper, one grouped before/after native PodMetrics check, and one grouped before/after read-only log check. Total expected count: 14, including the original 11.

## Bounds and limits

The existing fixture requests 5m CPU and 8Mi memory and continues to serve its fixed marker. No workload load is generated. Metrics Server installation and PodMetrics polling are bounded by the helper's command timeouts and a 100-second deadline for each sample; log reads are capped at 100 lines and 15 seconds. All additional resources are in the case-owned Kind cluster, which the normal runner deletes on completion. The dynamic Kind profile and generated private material are under the runner's temporary directory.

This demonstrates a fresh resource-metrics read and native container-log read for one synthetic Pod in this Kind profile. It does not establish production log forwarding, durable collection, monitoring alert behavior, metrics quality under workload, scheduling under contention, or real cluster capacity protection. The existing 11 checks and their claim limits remain unchanged.

## Dependencies

- Existing lab runner's normal `run` path and local Kind v1.36.1 node image.
- OpenSSL, curl, kubectl, and access to the pinned official Metrics Server v0.8.1 release manifest and digest-pinned image, as in SAF-K8S-1002-005.
- No new Python package or real credential is introduced.
