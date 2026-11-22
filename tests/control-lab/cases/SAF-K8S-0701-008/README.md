# SAF-K8S-0701-008 — Immutable versions and artifact retrieval

```sh
python3 lab.py test SAF-K8S-0701-008 --docker-context desktop-linux
```

The fixture puts two distinct dataset and artifact snapshots into
immutable ConfigMaps. It retains separate immutable metadata records
for v1, v2 and reuse of the original v1. Each record binds the selected
dataset revision and artifact to independent SHA-256 digests.

A server dry-run allows replacing a mutable record and refuses an
equivalent update to the immutable record. Three independent Jobs
retrieve and verify the selected versions, including v1 after v2 exists.
Two negative Jobs retrieve substituted bytes and fail the actual digest
check, separately for the artifact and dataset.

The test checks version selection and content integrity for Kubernetes
fixtures. Actual checkpoint lineage, pipeline identity, approved sources,
backend retention and reproducibility of training outputs require
production evidence.

- [Kubernetes v1.36 immutable ConfigMaps](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/configmap/#immutable-configmaps)
- [OCI content descriptors](https://github.com/opencontainers/image-spec/blob/main/descriptor.md)
