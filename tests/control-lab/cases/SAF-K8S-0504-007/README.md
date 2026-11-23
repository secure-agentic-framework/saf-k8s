# SAF-K8S-0504-007 workload federation

Run the control with the framework lab runner. It creates a fresh Kind cluster
and verifies two SPIRE 1.16.0 trust domains with separate root authorities,
workload identities, and Kubernetes bindings. Private keys stay in memory in
their own fixture containers. The probe validates the exact server SPIFFE ID.
The verifier logs only synthetic identities and TLS or HTTP outcomes.

The same approved B workload fails certificate verification before federation.
After SPIRE A refreshes B's bundle over the authenticated endpoint and
provides it through the Workload API, the same B workload gets HTTP 200.
A second B workload passes certificate verification and gets HTTP 403.
Independent clusters and production refresh, recovery, and governance are
separate items in Beads.
