# SAF-K8S-0103-015 Authenticated scheduler extender and approved scheduler selection

Run an official kube-scheduler process with a separate reviewed profile in disposable Kind. It calls one inert, identity-authorized extender over mutual TLS and actually binds the approved fixture Pod. The API rejects a Pod requesting an unapproved scheduler after the admission policy is enabled. Fresh certificate material is discarded with the cluster. Production scheduler inventories, access paths, operating approval and provider or multireplica deployment evidence are separate.

## Caller authorization comparison

A second fixture certificate chains to the same approved CA and carries a
different, unapproved client identity. Over verified TLS, one inert call
reaches the owned extender and receives HTTP 403 with no authorized-call
receipt. The approved scheduler still calls the same extender and binds its
allowed Pod. Adopt the comparison for each approved custom scheduler and
extender identity and route. Review trust, access, allowed node selection,
least-privilege API roles and organizational approval.
