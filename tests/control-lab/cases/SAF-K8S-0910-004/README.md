# SAF-K8S-0910-004 federated-round fixture

`case.py` exports `run(lab)`. The runner supplies one disposable source Kind cluster and its
`lab.cluster`, `lab.kubeconfig`, `lab.kubectl`, `lab.command`, `lab.check`, `lab.block`, and
`lab.evidence` interfaces. The case uses the adjacent pinned Python runtime helper and the
adjacent owned-peer helper to create a separately named second Kind cluster on the private fixture
bridge. The helpers own image pin verification and peer lifecycle. Running `run(lab)` therefore
requires a lab supervisor with Docker, Kind, kubectl, OpenSSL, and permission to create disposable
fixture resources; this implementation turn did not invoke those programs or run the case.

The receiver starts with round checks disabled. An authenticated source participant submits a
stale, old-protocol vector containing only `[1, 0, 2]`; the case verifies acceptance and reads the
receiver's actual service state with a separately authenticated observer. An admin identity enables
the exact round membership and protocol. A second stale vector then receives the exact
`409 round_mismatch` response. Wrong-protocol and identity-to-cluster membership fixtures also
receive exact refusal responses. A fresh observer read after every refusal must equal the complete
pre-request receiver state. The approved source and peer participants then submit `[2, 4, 6]` and
`[4, 6, 8]` for the current round; a duplicate from the first participant is refused without
changing state. The receiver records both unique contributions and computes integer sum
`[6, 10, 14]` and coordinate mean `[3, 5, 7]` for that exact round.

All client/server traffic uses short-lived fixture certificates, verified server DNS identity,
TLS 1.2 or newer, and required client certificates. Participant URI identities bind to their
expected cluster labels. Only the observer URI can read state; the participant read denial is part
of the positive receipt. The mTLS keys and certificate material stay in the runner's temporary
fixture directory and Kubernetes Secrets and are excluded from the JSON receipt.

## Receipts and limits

`lab.check` records bounded `red`, `green`, and `positive` checks; the case writes
`lab.evidence/federated-round-coordination.json` with exact fixture responses and observer state.
The red check intentionally passes when the unsecured baseline accepts the stale fixture. Green
requires exact refusal and unchanged receiver state. Positive requires two approved contributions,
observer-only readback, and the deterministic aggregate.

This is source for a runnable two-cluster fixture, not evidence that the fixture was executed.
Coverage is limited to one process-local receiver, two synthetic participants, one stale round,
one exact protocol, mTLS identity mapping, duplicate prevention, membership, and state readback.
It does not implement or establish secure aggregation, differential privacy, privacy budgets,
Byzantine tolerance, poisoned-update detection, production SPIFFE/SPIRE federation, durable state,
cluster-wide audit, or production deployment coverage. The baseline and receiver are case-owned;
no external endpoint or infrastructure outside the disposable lab is targeted.
