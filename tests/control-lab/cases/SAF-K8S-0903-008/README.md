# SAF-K8S-0903-008 — Budget-aware scale suppression

A local reconciler updates the native Deployment scale subresource through a
dedicated ServiceAccount. The controller Pod hosts a loopback-only fixture.
The API server permits reads and patches of one named scale resource. The
driver checks the real requested, Ready, and Available replica counts.

With the policy off, fixed projected demand of 15 units reaches three inert
replicas. With a cap of 10, identical demand receives HTTP 429 and the
current capacity stays available. Demand at the cap is admitted. Demand
below the cap allows recovery to one replica. The test uses synthetic costs
and an inert CPU Deployment. It tracks cloud budgets and accelerator
capacity as separate deployment evidence.
