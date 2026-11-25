# SAF-K8S-0910-020 cross-cluster transport

Run `python3 lab.py test SAF-K8S-0910-020` in the control-lab directory.
Each arm owns a source cluster and a peer cluster. The only test path is
the owned peer node's dynamically assigned NodePort.

The ordinary test response starts on plaintext. After the Service changes
to the TLS-only port, plaintext and unrelated trust fail. The source Pod
reads the fixed marker with the approved trust root and verified TLS 1.3.
No production traffic or credentials are used.

Verify route inventory, intermediaries, other transports, key lifecycle,
performance and encryption of every required production hop separately.

## Verify an adopting implementation

For each governed AI data path, record source workload and identity,
destination service and identity, route/port, protocol and negotiated TLS
version, trust anchor and certificate identity, and the observation
timestamp. Include forwarded, fallback, retry and failover routes, plus
gateways, proxies, service meshes and TLS termination points. At each
termination, capture the effective TLS settings and peer validation result.
Verify no governed path can silently fall back to cleartext. Identify the
approved cryptographic use and algorithm baseline, CA/key owner,
renewal/revocation process, and evidence that configuration applies to the
observed route. Preserve redacted configuration exports and a flow inventory
with evidence IDs linking each route to its handshake or telemetry result.
Record uncovered paths as gaps.

## Applicable NIST evidence

NIST SC-8 requires protecting confidentiality and integrity of transmitted
information. Its enhancement SC-8(1) specifically allows cryptographic
mechanisms, including TLS. SC-13 requires the organization to determine
cryptographic uses and implement the selected types. SA-8(18) is “Trusted
Communications Channels.” The existing `supports / moderate / conditional`
rows are correctly bounded if the conditions remain tied to actual deployed
routes and required protections. A single route's synthetic pass is not
enough to make those conditions true for the deployment.

[NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final).
