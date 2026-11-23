# SAF-K8S-0802-004 Firmware version and approved change reconciliation

A real read-only Kubernetes Job checks an immutable synthetic inventory against owned fixture change windows and emits a structured result. It distinguishes a permitted version change, version drift, an unchanged observation, and an unverified integrity input. The fixture exercises policy logic and a local Job report. It does not inspect firmware, monitor DCGM telemetry or verify hardware trust.
