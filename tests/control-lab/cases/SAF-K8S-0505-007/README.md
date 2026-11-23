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
