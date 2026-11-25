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

## Verify an adopting implementation

Inventory both deployed clusters and SPIRE trust domains, root provenance, federation endpoint identities, permitted network path and accountable owners. Verify authenticated bundle refresh and rollover between those clusters, including exact foreign SPIFFE identities accepted by each relying party and identities that remain denied. In a controlled maintenance window or preproduction environment, verify federation removal, stale/unknown bundle behavior and recovery without broadening trust. Retain root/bundle fingerprints, refresh/rollover events, relying-party allow/deny records, failures and approval history.
