# SAF-K8S-0504-001 workload identity and current authorization

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0504-001 --docker-context desktop-linux
```

The case installs pinned Istio in a fresh Kind cluster. The destination proxy
records the certificate URI of each source identity. Both identities can reach
both routes before policy activation. After activation, two fresh client
proxies use the same ServiceAccounts. The approved identity still reaches the
allowed route, and the other three combinations receive HTTP 403.

The evidence covers the fresh-client authorization matrix, plus the established
HTTP/1.1 application connection on both an approved and a denied route after
policy acknowledgement. See the connection continuation and replacement
section for observed lifecycle detail.

[Istio authorization](https://istio.io/latest/docs/reference/config/security/authorization-policy/)
· [Istio peer authentication](https://istio.io/latest/docs/reference/config/security/peer_authentication/)

## Verify an adopting deployment

Use this checklist for an owner-approved review of one deployed Istio mesh and representative workloads. The portable case is a local reference: two service identities, one destination, two harmless HTTP routes, strict peer mTLS, and an identity/path `AuthorizationPolicy`. It does not establish fleet coverage or production policy rollout.

1. **Define the owner-approved scope.** Record cluster and mesh identity, Istio control-plane version/revision, sidecar or ambient mode, in-scope namespaces/workloads/Services, workload service accounts, policy exceptions, and the transport/protocol paths that the service owner has authorized for review. Do not include secrets, tokens, private keys, or unrelated request bodies in evidence.
2. **Confirm desired and reconciled policy.** Retain the reviewed `PeerAuthentication` and `AuthorizationPolicy` resource metadata/spec (redacted only for unrelated labels/annotations) and the change/review reference. Confirm the policy selects the intended workload and inspect the effective authorization policy at representative destination proxies with the version-matched `istioctl x authz check <pod>.<namespace>` (called `istioctl experimental authz check` in some CLI releases). A Kubernetes object existing or a Deployment being ready does not alone show that the intended proxy configuration has arrived.
3. **Confirm control-plane acknowledgement.** After the owner-approved rollout, capture version-matched `istioctl proxy-status` for every relevant source and destination proxy. Istio defines `SYNCED` as Envoy having acknowledged the last configuration sent by Istiod; `STALE` means an update was sent without acknowledgement, and a missing proxy is not currently connected to Istiod and will not receive configuration. Record the observed state and time. Treat stale/missing proxies as unresolved rollout evidence rather than assuming propagation.
4. **Record harmless owner-side behavior.** On an approved synthetic or non-sensitive route, record the observed destination peer principal, configured mTLS mode, one expected permitted identity/route pair, and the resulting normal service response. Capture only status, route label, principal classification, proxy identity, and timestamp; avoid credentials and payloads. If the owner already has an approved negative authorization check, retain its sanitized result and corresponding proxy evidence; do not create a new denial or attempt to bypass an existing policy for this checklist.
5. **Record connection lifecycle.** The local test keeps one approved HTTP/1.1 application socket through policy activation, records the observed destination connection IDs, and checks an approved response after graceful source Pod replacement. For the deployment, record actual connection lifetimes and approved policy-change procedures. Verify any required HTTP/2 stream, upstream pool, drain, or reconnect behavior with evidence from the adopted protocol and proxy configuration.
6. **Bound the conclusion.** Attach the inventory coverage denominator, exceptions, dates, approving owner, and evidence links. State which namespaces/proxies/routes were checked and which remain out of scope. The paired reference runs passed 16 checks each on separate deleted Kind clusters (Kubernetes v1.36.1, Istio 1.32.0); they establish only the local reference behavior described above.

## Versioned Istio references

- [Istio 1.32 PeerAuthentication](https://istio.io/v1.32/docs/reference/config/security/peer_authentication/): `STRICT` requires an mTLS tunnel with a client certificate.
- [Istio 1.32 AuthorizationPolicy](https://istio.io/v1.32/docs/reference/config/security/authorization-policy/): peer principals derive from mTLS certificates; identity and request operations are policy inputs.
- [Istio 1.32 `istioctl proxy-status`](https://istio.io/v1.32/docs/ops/diagnostic-tools/proxy-cmd/): last-sent/last-acknowledged xDS state and meanings of `SYNCED`, `STALE`, and a missing proxy.
- [Istio 1.32 `istioctl` reference](https://istio.io/v1.32/docs/reference/commands/istioctl/): version-matched CLI reference, including effective authorization-policy inspection where supported by that release.

## Approved connection continuation and replacement

The approved HTTP/1.1 request is repeated over the same application socket
after policy reconciliation. The raw fixture record preserves the destination
Envoy connection IDs and any change independently. Continued use of the
application socket permits a different destination connection. The additive
check then sends the fixed `/other` request on that same already-open socket and
requires the destination proxy to return HTTP 403 for the approved identity.
It follows with the fixed `/allow` request and requires HTTP 200. The separate
`established-path-enforcement-observations.json` records the exact route/status
connection IDs and whether the 403 response leaves the application and
destination connections open for the allowed follow-up. It does not infer same
connection use from the later request if the denied response closes it. The owner
then deletes the exact client Pod using a 20-second grace period. Both Pod
specs carry the pinned native-sidecar lifecycle hook. The approved
replacement has a distinct UID and returns the fixed marker using the same
approved identity over a new destination connection.

The pinned Istio 1.32.0 `istioctl proxy-status --output json` output provides
structured status for the exact case-owned source and destination proxies.
The test checks CDS, LDS, EDS, and RDS status after policy activation and
after reconnection. The composed candidate has 17 checks: the 16 published
assertions plus one grouped established-request route check. This evidence
covers only fixed HTTP/1.1 routes in the owned fixture. Fleet deployment
coverage, other protocols, existing in-flight streams, and unrelated pooled
connections require adopter evidence.

The application socket and destination proxy connection are observed
independently. The first live observation retained the same application socket
for the approved, denied, and approved requests while Envoy reported a new
destination connection for the denied request. The assertion requires
the application connection to carry the expected decisions and the destination
proxy to report each request with the expected identity, path, and response.
The raw record keeps the individual destination connection identifiers for each run.
