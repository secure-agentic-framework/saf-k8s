# SAF-K8S-1001-007 — Supplemental application telemetry

```sh
python3 lab.py test SAF-K8S-1001-007 --docker-context desktop-linux
```

Two finite Pods send an actual local HTTP request to a synthetic application.
Each Pod generates its event identifier at runtime. With the collector disabled,
the app succeeds and there is no supplemental record. With the collector
enabled, the same request flow persists exactly one record. The test compares
that persisted event with the five approved fixture fields and checks that the
synthetic prompt did not reach the file.

An unrelated ConfigMap read proves that the Kind API server's Metadata audit
stream captured a completed API request and omitted its bodies. Neither of the
application event identifiers occurs in that active stream. The retained result
includes the scoped assertions and no raw audit data.

The reference design uses application events and request metadata by default.
Istio's standard log format supplies HTTP metadata. GPU process accounting needs
a validated process event source. NVIDIA documents a separate process statistics
API with watches distinct from the GPU metrics exported by DCGM Exporter.
Real GPU processes, mesh deployments, forwarding, and production retention
require additional evidence. Collection of selected payload fields requires its
own approved instrumentation and evidence.

[Kubernetes v1.36 audit](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/) ·
[Istio access logs](https://istio.io/latest/docs/tasks/observability/logs/access-log/) ·
[NVIDIA GPU metrics](https://docs.nvidia.com/datacenter/dcgm/latest/gpu-telemetry/dcgm-exporter.html) ·
[NVIDIA process accounting](https://docs.nvidia.com/datacenter/dcgm/latest/dcgm-api/dcgm-api-process-stats.html)
