# SAF-K8S-1001-037 — WORM retention for Kubernetes audit records

```sh
python3 lab.py test SAF-K8S-1001-037 --docker-context desktop-linux
```

From the SAF-K8S checkout, run `python3 tests/control-lab/lab.py` with the same arguments. The runner starts a Kubernetes v1.36.1 Kind cluster. It selects the native Metadata-level audit event for a named synthetic ConfigMap create and preserves its exact JSONL bytes and SHA-256.

A digest-pinned Versity v1.9.0 S3 gateway stores two copies under case-owned keys. The same fixture identity permanently deletes the unlocked version and receives a denial when it requests deletion of the retained version. A separate request attempts to shorten the COMPLIANCE retention interval. Retrieval by version ID returns the original digest before and after these requests.

A successor upload produces a different version and becomes the current result. A versionless delete then creates a marker and hides the current key from an unversioned GET. The original retained version remains retrievable by its version ID.

The object storage uses ephemeral Kind volumes and a two-day fixture retention period. The evidence covers one native audit record and the S3 data plane of this backend. Deployed audit ingestion, policy enrollment across applicable log classes, storage administration boundaries and sustained retention require production evidence.

[Kubernetes auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/) · [Versity v1.9.0](https://github.com/versity/versitygw/releases/tag/v1.9.0) · [S3 Object Lock version semantics](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
