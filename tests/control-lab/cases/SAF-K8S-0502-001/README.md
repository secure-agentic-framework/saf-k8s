# SAF-K8S-0502-001 — Compare CNI candidates against an approved profile

Run the isolated comparison from the lab checkout.

```sh
python3 lab.py test SAF-K8S-0502-001 --docker-context desktop-linux
```

From the framework checkout, invoke `python3 tests/control-lab/lab.py`.
The case uses pinned local Kind and Kubernetes, and compares bundled
kindnet with pinned Cilium. Both admit the baseline paths, deny the
governed path and preserve an approved marker path after policy. The
profile also names Cilium's embedded Hubble JSON observer. That specific
requirement yields different selection decisions for the two candidates.

The case records five successful time samples for each candidate in
`selection-record.json`. Each timing uses a host monotonic clock around
an exact policy-enabled request. It includes the Kubernetes API exec path,
fixture server and local Docker VM. Use those samples to see how to preserve
an observed comparison. Apply any selection thresholds to measurements
taken in the adopted environment.

## Evidence for the selected features

- For cross-node Cilium-managed Pod traffic, the WireGuard example observes
  the actual peer configuration, counters and continuity for the marker in
  both directions. [SAF-K8S-0502-002](https://github.com/secure-agentic-framework/saf-k8s/blob/4afc370e2c17700efd2253c18b9281bf31845ffa/tests/control-lab/cases/SAF-K8S-0502-002/README.md).
- For IPv4 names and HTTP methods, the Cilium fixture separates DNS
  resolution from allowed connections and verifies policy for the chosen
  HTTP operation. [SAF-K8S-0501-004](https://github.com/secure-agentic-framework/saf-k8s/blob/0e06d9f06eb306a1052bfc270c38c31085fb2c53/tests/control-lab/cases/SAF-K8S-0501-004/README.md).

## Verify the adopted selection

1. Agree the required ingress, egress, encryption, name, L7, observability
   and performance conditions for the workload paths before evaluating
   candidates. Record the minimums, reviewers and compensating-control owner.
2. Capture the exact versions and configuration of each candidate, including
   provider limitations, image and chart digests, policy settings and
   enabled interfaces. Connect each criterion to an observable outcome.
3. Use approved disposable workloads and compare healthy ungoverned,
   governed denied, and exact permitted paths. Inspect effective policy
   decisions and protected observation fields for the relevant identities,
   IP families, protocols, address translation and gateways.
4. Where required, verify encryption across the actual plaintext boundaries
   and used interfaces. Verify destination-name enforcement, the resolver
   and TTL path, and positive and negative L7 operations with owned markers.
5. Benchmark repeated workloads under comparable hardware, traffic and
   security-enabled configurations. Measure tail latency, throughput, loss,
   and CPU/memory against preapproved limits. Capture equivalent baseline
   samples, the timing method, the load pattern and the resulting decisions.
6. Retain independent evidence, required flow export and retention checks,
   the selected version/configuration, exception approval, residual routes
   and the trigger for re-evaluating a new release or migration.

[Kubernetes NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)
and [Cilium v1.20 performance tuning](https://docs.cilium.io/en/v1.20/operations/performance/tuning/).
