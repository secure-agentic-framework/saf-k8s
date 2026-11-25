# SAF-K8S-0903-008 budget-governed inference scaling

Run from the framework checkout:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0903-008 --docker-context desktop-linux
```

The fixture reconciler can read and patch the scale subresource of one owned
Deployment. The test compares the same synthetic projected demand with the
budget policy off and on, then verifies below-cap, exact-cap, and recovery
behavior. The over-cap decision preserves Ready capacity and refuses further
scale-out.

An HTTP route in the same fixture process reads the evaluated budget state.
The normal synthetic response is available below cap. One harmless request
receives HTTP 429 while over cap, and the normal response returns after
recovery. The process runs on disposable Kubernetes. The serving route uses
local loopback with fixed requests and no model execution or actual cost feed.

## Verify an adopting implementation

1. Identify the authoritative cost or forecast input, its signer or identity,
   scope, age limit and expected update latency. Inventory all autoscaler
   writers, selected accelerators, scale targets and approval thresholds.
2. Exercise below-cap, exact-cap, approved over-cap and stale-source
   decisions in a representative environment. Verify the effective replica
   count, Ready capacity, feedback to existing scale writers, and safe
   behavior if cost evaluation becomes unavailable.
3. Send an approved canary through the actual serving entry point. Verify the
   configured throttling, queue or fallback response, its bounds, and
   service recovery after the cost decision clears. Preserve time-aligned
   scale, decision and response evidence.
