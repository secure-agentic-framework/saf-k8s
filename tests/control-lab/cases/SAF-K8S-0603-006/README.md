# SAF-K8S-0603-006 — TUF update verification

Run `python3 lab.py test SAF-K8S-0603-006` from the control lab.

Two disposable Kubernetes Pods act as the publisher and client. The
publisher generates synthetic Ed25519 keys and signed metadata for a
benign UTF-8 release note. The lab passes the authenticated bootstrap root
to the client via the Kubernetes API. The client reads update metadata and
the target only from the case's ClusterIP Service.

The pinned reference client verifies expiry, role thresholds, signed parent
version and digest binding, metadata download length, and target integrity.
It rejects rollback after a successful update. A new root must satisfy
the thresholds of both old and new root metadata; the test exercises
both the allowed rotation and a rotation with only the new signatures.

The fixture uses software-generated keys. Threshold design, actual custody,
HSM integration if required, and signing and emergency recovery ceremonies
need separate deployment evidence.
