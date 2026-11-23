# SAF-K8S-0909-012

Run `python3 tests/control-lab/lab.py test SAF-K8S-0909-012` from the repository root.

The unmonitored fixed fixture forwards a synthetic candidate. The governed fixture detects a digest discrepancy, restores its active pointer to a known approved generation, records the scoped hold, and delivers a minimal alert to a separate receiver. An independent read-only workload verifies retained state, and the held generation cannot reach the consumer. A later approved ordinary generation passes.

Verify deployed index change sources, operational alert delivery and handling, release timing, recovery guarantees and concurrent behavior separately.
