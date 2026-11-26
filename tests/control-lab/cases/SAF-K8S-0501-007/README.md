# SAF-K8S-0501-007 — East-west flow monitoring and a fixed alert rule

Run from the lab repository:

```sh
python3 lab.py test SAF-K8S-0501-007 --docker-context desktop-linux
```

From the framework repository use `python3 tests/control-lab/lab.py`. The
case installs the pinned Cilium and embedded Hubble observer on a disposable
Kubernetes cluster. It observes owned TCP/18080 paths from the training
namespace to the pipeline and inference namespaces. A live application
response and a Hubble event independently confirm the observed path.

The baseline reaches both listeners. With the scoped NetworkPolicy active,
the permitted training-to-pipeline request still succeeds. The other
request is denied and appears as `POLICY_DENIED` with the expected workload,
namespace and port. A local fixed rule evaluates these captured events.
It emits one deduplicated alert for the baseline forwarded unexpected edge,
stays quiet on the permitted pipeline and policy-denied inference events, and
emits nothing when disabled for the same observed candidate.

The receipt preserves the native Cilium release, path decisions and
alert predicates. Raw fixture events are in `hubble-events.json`.
`anomaly-rule-evaluation.json` captures the local result. The case uses a
single exact rule. The general detection engine, production monitoring
and externally delivered alerts need separate verification.

## Verify the adopted monitoring stack

1. Inventory the enrolled training, inference, notebook and pipeline
   namespaces and relevant intermediate and cross-node paths. Record
   the enforcing CNI, sensor version, observation points and collection
   filters. Identify owners and effective permitted and denied paths.
2. Select harmless owned source and destination markers in a representative
   environment. Record a permitted path, a governed denied path and one
   test-only unexpectedly permitted path. Compare the application result
   with the exact observer event and independent destination health.
   Confirm direction, destination port, workload identities, verdict and
   reason. Include a denied-flow alert rule when expected and approved.
3. Test the adopted rule independently against all three outcomes. Verify
   active and disabled behavior, clear and stale state, deduplication,
   expected alert route and the correlating flow fields. Compare with the
   separately approved baseline and document known blind spots and
   unobserved paths.
4. Verify successful delivery, access restriction, integrity and retention
   at the actual SIEM or monitoring receiver with a benign test marker.
   Verify collection when healthy and an observable loss signal during a
   controlled receiver interruption. Confirm that a reviewer can retrieve
   the specific test event, correlate it with the trigger, and handle
   duplicate delivery or timing delays.
5. Retain the effective policy and rules at their reviewed revisions,
   independent application and flow observations, receiver evidence,
   approved retention and the responsible team's sign-off.

References
[Cilium Hubble setup](https://docs.cilium.io/en/v1.20/gettingstarted/hubble_setup/)
and [Hubble Flow API](https://docs.cilium.io/en/v1.20/_api/v1/flow/README/).
