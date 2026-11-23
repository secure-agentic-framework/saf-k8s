# SAF-K8S-0603-004 — Cryptographic algorithm migration

Run `python3 lab.py test SAF-K8S-0603-004` from the control lab.

The test creates five immutable synthetic lifecycle artifacts and uses a pinned
Cryptography build to sign their canonical digest manifest. The case exercises
classical-only policy, a dual-signature requirement, and an ML-DSA-65 cutover.
It rejects missing signatures, another signing key, a changed digest, and a
validly signed manifest with omitted coverage. The approved release starts a
Pod that checks the exact governed inputs.

Lifecycle coverage, retention, KEM-related encryption, trusted key custody,
signed policy storage and organization-wide migration and rollback require
deployed evidence.
