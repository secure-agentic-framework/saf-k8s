# SAF-K8S-0909-014

Run `python3 tests/control-lab/lab.py test SAF-K8S-0909-014` from the SAF-K8S repository root. The case uses local Kind, the pinned Cosign verifier, and disposable persistent claims.

The baseline indexes a benign alternate document. In the governed path, a Cosign init container verifies the detached signature over the approval document with a separately pinned local public key. An altered approval never starts ingestion. A valid approval bound to different document bytes also yields no chunk or storage writes. The positive case persists the approved chunks, known retrieval, and approval receipt. Separate read-only Pods observe the results.

Verify production authority, signer lifecycle, real source identity and freshness, alternate intake routes and update policy, and recovery of the storage commit paths.

[Sigstore signature verification](https://docs.sigstore.dev/cosign/verifying/verify/)
