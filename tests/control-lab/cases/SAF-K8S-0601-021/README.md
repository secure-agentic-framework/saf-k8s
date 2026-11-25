# SAF-K8S-0601-021 registry network restriction

Run `python3 lab.py test SAF-K8S-0601-021` from the control-lab directory.

Two test clients make real OCI API requests to the owned registry through its
Service and directly to its Pod. Both succeed in the baseline. After kindnet
enforces the recorded NetworkPolicy, only the approved source can reach either
route. The isolated fixture does not use a public endpoint or a real credential.
Verify provider, mirror and private endpoint paths separately for each deployment.

## Verify an adopting implementation

Enumerate public/private endpoints, Service/Pod/NodePort
routes, mirrors, cache endpoints, and provider network controls. From approved
workload sources prove registry reads succeed; from an unapproved but
authorized test source prove each alternate route is denied. Reconcile identity
authentication and egress rules with the published registry and document
exceptions and cache behavior.
