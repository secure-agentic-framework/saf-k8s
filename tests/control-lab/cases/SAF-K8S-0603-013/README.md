# SAF-K8S-0603-013 — Attestation checks at lifecycle transitions

Run `python3 lab.py test SAF-K8S-0603-013` from the control lab.

A pinned harmless image becomes a staged OCI artifact in the fixture registry.
A build signer records its exact input and output. The promotion step rejects
a stale build or an incorrect input, verifies the approved build record, then
copies the exact bytes to a different repository. A distinct signer binds
that promotion to the build envelope and staged subject.

The deployment gate rejects records with the wrong signing key or predecessor
and admits the valid chain. Kind runs the exact promoted digest. A third signer
records the observed deployment UID. The downstream check verifies that record
for the actual deployment and refuses a different UID.

The fixture uses local DSSE signing and in-toto statements. Each stage has a
separate short-lived key. Production release identities, secure clock, policy
distribution, coverage of rollout paths, and audit retention require separate
evidence.

## Verify an adopting implementation

Map all release transitions and bypass routes to their
actual signer/identity, verified subject digest/index, trust roots, policy
revision, freshness source, and deployment receipt. Submit inert wrong-stage,
stale/replayed, and mismatched-index evidence at each transition; show denial
and preserve the previous approved release. Retain root rotation, audit
delivery, and coverage evidence for each entry point.
