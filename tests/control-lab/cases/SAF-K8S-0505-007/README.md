# SAF-K8S-0505-007 managed administrative path

The private local relay makes one fixed ConfigMap read through the
current Kind API. The upstream API uses its own CA and a short-lived
ServiceAccount token whose Role admits a read of that one object.
The relay verifies clients against a freshly generated fixture CA.

Both enrolled clients can read before relay authorization. After the
rule is activated, the approved identity receives the exact API marker,
and the other identity receives HTTP 403. The evidence records each
verified client identity, decision, and whether it called the API.
Fixture keys and the token stay in the run.

Deployed network routing, VPN or bastion configuration, multifactor
authentication, automation access, and log delivery remain separate.

## Verify an adopting implementation

Map actual operator, automation and break-glass routes to the API server, including bastion/VPN, private endpoints, provider control-plane IAM, alternate DNS/address-family routes and denied adjacent paths. Verify human MFA and automation identity separately, then review effective Kubernetes and provider permissions for each role; test a harmless authorized read and a denied neighboring read through the approved relay. Confirm unauthorized identities are denied before reaching the API and that break-glass use is separately authorized, time-bounded and reviewed. Correlate sanitized gateway decisions with Kubernetes audit events and prove retention, alert routing and incident ownership.
