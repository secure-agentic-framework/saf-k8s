# SAF-K8S-0905-043 Durable OCI ML-BOM linkage

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-043 --docker-context desktop-linux` from the framework checkout.

Two inert OCI model versions have separate manifest digests. A pinned Distribution registry discovers the ML-BOM attached to the exact reviewed model. The test validates the attachment subject and the original payload bytes, leaves the second model unattached, and repeats retrieval after replacing the source registry Pod.

A separate destination registry starts without the subject. Promotion reads the exact manifests and blobs from the source, verifies their identities and sizes, and copies those bytes to separate storage. The destination discovers the matching ML-BOM for the original subject, leaves the second version unattached, and retrieves the same attachment after replacing its Pod.

## Verify an adopting implementation

Inventory the actual artifact and OCI attachment formats, model version identity, approved publication and read principals, registry versions, and every storage, replication and promotion path. Compare the model and ML-BOM digests and the attachment subject at each target. Verify that the distinct model version cannot resolve the wrong record. Capture the approved source and destination, configuration revision, exact subject, attachment and payload digests, and independent readback.

Exercise retrieval after the deployed registry restarts and after approved recovery. Confirm the actual retention and garbage collection behavior still protects the linked record, and verify replication and backups across the intended lifecycle. Independently validate the quality of ML-BOM generation when that claim applies.

- [OCI Distribution v1.1.1 referrers](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#listing-referrers)
- [Kubernetes v1.36 PersistentVolumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/persistent-volumes/)
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
