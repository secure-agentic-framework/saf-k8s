# SAF-K8S-0910-004 federated-round coordination

`python3 tests/control-lab/lab.py test SAF-K8S-0910-004 --docker-context desktop-linux`

The fixture starts two owned Kind control planes using the adjacent pinned
runtime and peer helpers. It needs Docker, Kind, kubectl, and OpenSSL.
The clients exchange only inert integer counts with a private mTLS receiver.
An authenticated observer reads the receiver's actual state after each attempt.

The baseline accepts a stale vector. A separately authenticated administrator
enables round and membership checks. The receiver then refuses stale rounds,
wrong protocols, a mismatched participant identity, and duplicate contributions
without changing state. Two approved participants contribute distinct vectors.
The observer reads their exact current-round aggregate, and an ordinary
participant is refused the observer's read operation.

The raw receipt records the two API and participant Pod identities. The
deterministic receipt preserves the observable decisions and aggregate for
comparison across runs. Production federation, durable state, recovery,
secure aggregation and privacy controls require separate evidence.


## Supplemental observer authorization witness

The published case has four assertions. Its observer check uses the same authenticated observer identity to submit a
well-formed fixed vector `[1, 1, 1]` for the current round. The receiver must return
`403 participant_identity_refused`; a separate observer-authenticated state read must exactly match
the pre-request state. This distinguishes an authenticated nonparticipant principal from a valid
participant that supplies the wrong cluster label.

The added assertion covers only the fixture receiver's authorization decision. Certificates and URI
identities are generated for this disposable case; this does not prove deployed SPIFFE/SPIRE issuance,
cluster-of-origin credential provisioning, or production federation behavior. The original secure
aggregation, differential privacy, durable state, recovery, monitoring, and fleet-scale limitations
remain.

## Scratch-only synthetic verified-root policy witness

This candidate preserves the four published assertions and adds one bounded check. A separately
generated and explicitly named disallowed test CA signs a certificate with the exact approved
participant-A URI identity. The disposable receiver trusts the fixture CA bundle at TLS, then allows
contributions only when the URI identity is paired with the exact approved root SHA-256 computed
from that generated public root certificate's DER encoding. At the receiver, Python 3.13's verified
TLS chain must include the observed leaf and a terminal root; policy hashes the terminal DER bytes.
From the owned peer cluster, the disallowed certificate submits the exact current round, protocol
and `cluster-a` label
with fixed numeric counts. The receiver must return `403 participant_trust_root_refused` with the
observed verified terminal-root fingerprint; the authenticated observer independently confirms
that the parent round state is unchanged. The existing approved A and B clients still submit
successfully and produce the exact existing aggregate.

This is a synthetic verified-root-and-identity policy comparison. A trusted root fingerprint does
not attest the physical source cluster, prove SPIFFE/SPIRE issuance or production membership, or
resist credential copying. It exercises no real model or provider path. Expected total: five checks,
four published assertions plus one additive check; no extra Kind cluster or PVC. The added peer Pod
has a 5m CPU/16Mi memory request and 100m CPU/64Mi memory limit. Raw decision details, both fixture
root fingerprints and the observed rejected-chain root fingerprint are included in
`federated-round-coordination.json`.

The catalog revision defines applicable federation controls by deployed trust
boundary and threat assumptions. This replay demonstrates the fixed two-cluster
coordination path, approved service identities and observed participant
decisions over mutual TLS. Deployed credential provisioning, any required
privacy and robust aggregation composition, and monitoring need their own
evidence.
