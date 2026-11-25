# SAF-K8S-0903-007 — Native HPA replica bounds and stabilization

The native HPA controller scales a case-owned inert Deployment using a
deterministic metric from an aggregated HTTPS API. The provider serves only
the fixture metric and the APIService trusts the disposable serving
certificate. The first profile reaches four Pods. The guarded profile allows
one extra Pod per 30 seconds, caps the Deployment at three, and holds the
recent recommendation on a demand decrease before returning to one.

This exercises HPA mechanics. GPU metric collection, KEDA trigger behavior,
real inference capacity, and production time and resource limits require
separate evidence. KEDA's cooldown is specific to scaling to zero and its HPA
handles the 1-to-N range.

## Verify an adopting implementation

Validate the deployed HPA metrics API trust chain and metric meaning, then inspect target/min/max replica bounds, scale-up policy, and downscale stabilization. Exercise bounded demand rise and fall with representative inference/GPU metrics and confirm readiness and capacity. The fixture proves native HPA behavior using deterministic synthetic HTTPS demand. It does not prove GPU metrics, KEDA, or inference capacity.
