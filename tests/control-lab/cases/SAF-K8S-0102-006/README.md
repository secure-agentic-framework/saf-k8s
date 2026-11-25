# SAF-K8S-0102-006 Native API encryption key rotation

The disposable API server encrypts a dedicated public-marker resource. It uses the previous key for existing data and the next key for new writes during rotation. The test verifies the exact migration with a metadata rewrite and reads both owned markers after retirement of the old key. It restarts only the case's disposable API server at each transition.

The key values are ephemeral and held in a restrictive temporary config. Evidence retains only public key labels and boolean observations. Remote KMS, media encryption, production rotation policy and managed-control-plane operations require deployment-specific evidence.

## Pre-migration rollback comparison

The disposable API server temporarily selects the original key for new writes
while retaining both keys for reads. The exact new rollback write appears under
the original envelope. The earlier records keep their old and new envelopes
and remain readable. The fixture then restores the new writer, migrates both
records still under the old envelope, and verifies all three after retirement.
This reference exercises authenticated local-provider behavior. For managed
KMS, verify the release-specific provider key identifiers, active writer and
read-back, approved cadence, audit proof, migration counts, recovery readiness
and retirement. Keep key material out of evidence.

## Schedule and retirement planner

A fixed-clock synthetic comparison accepts a complete approved plan and
rejects plans with missing, self-issued or expired approval, an overdue
schedule, early retirement, a legal hold, or incomplete recovery coverage.
The fixture values exercise the decision boundaries. It records only
scenario outcomes and performs no key or backup action.

For adoption, record each active scheduled workflow, its approval and owner.
Confirm the actual writer version and compare each applicable record and
backup before and after migration. Retain scoped inventory, immutable hold
decisions and isolated recovery evidence for every dependent copy. Verify
remote-provider rotation and authorized retirement from the selected
provider's records and recovery observations.
