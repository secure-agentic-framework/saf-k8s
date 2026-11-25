# SAF-K8S-0910-021 cross-cluster endpoint and workload identity

Run `python3 lab.py test SAF-K8S-0910-021` from the control-lab directory.
Each arm starts two separately owned Kind clusters and uses a dynamic NodePort
on the verified test bridge. The approved and alternate callers each mount
only their own disposable certificate. Another caller has no certificate.

The baseline accepts the alternate certificate from the trusted fixture CA.
The governed service checks the actual caller URI as well. The client checks
the exact destination DNS name. The gateway logs the approved identity from
its verified peer certificate. This test uses case-issued certificates and
does not validate SPIRE, workload attestation or production trust federation.

## Verify an adopting implementation

Inventory each deployed accepting and initiating service, expected URI/DNS
identity, cluster/namespace and trust domain, issuer, trust roots, identity-
to-service binding, and all routes/intermediaries that can terminate or re-
originate TLS. For every route, retain a redacted effective trust/peer
configuration and a successful observed session showing the validated peer
identity. In a controlled non-production test, verify an unexpected same-
issuer identity and a hostname/URI mismatch are rejected. Document
certificate issuance, key custody, expiry, renewal, revocation, federation
and failure behavior. Show how logs identify the peer and correlate to the
connection without exposing credentials. Identify device endpoints
separately: report IA-3 only where an organization-defined device (not
merely a service instance) is actually identified and authenticated.

## Applicable NIST evidence

NIST IA-9 requires unique identification and authentication of organization-
defined services and applications before communication. This is the direct
clause for workload/service identities. IA-3 requires unique identification
and authentication of organization-defined devices before connection, so its
existing `supports / moderate / conditional` mapping is appropriate only for
device endpoints covered by the deployment. SA-8(18) is conditional support
where the deployed path establishes the approved endpoint trust and channel
protections. These conditions should be retained verbatim or equivalently
narrowly.

[NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final).
