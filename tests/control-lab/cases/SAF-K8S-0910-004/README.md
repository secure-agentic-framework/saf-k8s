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
