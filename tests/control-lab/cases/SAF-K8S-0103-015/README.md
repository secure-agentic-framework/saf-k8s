# SAF-K8S-0103-015 Authenticated scheduler extender and approved scheduler selection

Run an official kube-scheduler process with a separate reviewed profile in disposable Kind. It calls one inert, identity-authorized extender over mutual TLS and actually binds the approved fixture Pod. The API rejects a Pod requesting an unapproved scheduler after the admission policy is enabled. Fresh certificate material is discarded with the cluster. Production scheduler inventories, access paths, operating approval and provider or multireplica deployment evidence are separate.
