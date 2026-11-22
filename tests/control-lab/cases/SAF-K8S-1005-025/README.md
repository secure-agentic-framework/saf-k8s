# SAF-K8S-1005-025 — Bounded forensic evidence acquisition

Run with `python3 lab.py test SAF-K8S-1005-025 --docker-context desktop-linux`. The runner creates and deletes a fresh pinned Kind v1.36.1 cluster. The only custom mounts are a generated metadata-only audit policy and a temporary case-owned audit output directory.

The case reads real logs from a restricted, tokenless fixture Pod and allowlisted node metadata for its scheduled node. It correlates metadata-only successful Kubernetes audit events with the named fixture ConfigMap creation, Pod creation and log read. A single loopback TCP exchange between two sockets inside the Pod verifies exact fixed fixture bytes and emits only connection metadata. No packets, request bodies, arbitrary node files, or production artifacts enter the bundle.

The validator rejects a missing connection record and a changed record paired with the original manifest. It accepts the complete four-class evidence bundle when its hashes match. The structured assertions are repeatable on independent clusters, while the archived raw artifacts preserve local audit IDs and Kubernetes UIDs.

This scope leaves volatile memory and disk capture, CNI-wide production flow coverage, operational collection authority, retention, and real chain of custody for separate verification.

- [Kubernetes auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [NIST SP 800-86](https://csrc.nist.gov/pubs/sp/800/86/final)
