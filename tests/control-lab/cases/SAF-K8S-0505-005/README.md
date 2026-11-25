# SAF-K8S-0505-005 identity-based internal Service access

The test installs pinned Istio in a fresh Kind cluster. Two workloads in
separate namespaces use identically named ServiceAccounts. Before adding
authorization, both complete mTLS and reach the owned sensitive route.
The destination sidecar records each exact namespace-qualified SPIFFE ID.

After applying authorization, new client proxies use the same accounts.
The intended identity still reaches the route. The identical account name
from the other namespace receives HTTP 403 from the destination proxy.
The same-namespace account and route controls run alongside that check.

[Istio authorization](https://istio.io/latest/docs/reference/config/security/authorization-policy/)
· [Istio conditions](https://istio.io/latest/docs/reference/config/security/conditions/)

## Adopter verification

Inventory sensitive internal endpoints and namespace-qualified workload identities. For Istio, verify effective destination AuthorizationPolicy behavior for permitted identity and same-name identity from another namespace. For Linkerd, collect the deployed AuthorizationPolicy and MeshTLSAuthentication coverage where used. Separately verify admission/trust scope, application-layer authorization, workload attestation, incident monitoring and safe policy rollout on the actual traffic path.
