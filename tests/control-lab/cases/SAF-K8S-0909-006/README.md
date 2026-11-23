# SAF-K8S-0909-006

Run `python3 tests/control-lab/lab.py test SAF-K8S-0909-006` from the SAF-K8S repository root using a local Kind cluster and dynamic persistent volume provisioning.

The case snapshots a SQLite vector table and verifies that the snapshot and known retrieval survive replacement of its Pod. The ungoverned baseline activates a structurally valid alternate index whose known query returns the wrong result. The governed path restores the approved snapshot, checks the staged index against a separate immutable approval record and a known retrieval, and leaves the active database unchanged when the candidate fails. It rebuilds the index from the approved fixture records and removes a closed, named fixture generation without affecting the active query.

The fixture uses cosine lookup against a small synthetic vector table and one local volume. Independently verify the deployed index and migration compatibility, recovery objectives, copies and retention, and approved storage sanitization.

[SQLite Backup API](https://www.sqlite.org/backup.html) · [NIST SP 800-88 Rev. 2](https://csrc.nist.gov/pubs/sp/800/88/r2/final)
