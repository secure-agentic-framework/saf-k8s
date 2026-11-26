# SAF-K8S-0906-006 — Query exact stored training lineage

Run `python3 tests/control-lab/lab.py test SAF-K8S-0906-006 --docker-context desktop-linux` from the framework checkout.

Kubernetes Jobs work with synthetic source, transformation receipts and model bytes on case-owned volumes. The four checks observe an ungoverned baseline, deny missing and inconsistent exact receipt links, accept one linked approved artifact, and independently query the persisted lineage from a read-only Job. The query validates the approval edge and digests, resolves the approved artifact to its source and transformation, and resolves each approved input to the exact artifact. Ungoverned and unknown input lookups return no release records.

## Verify an adopted lineage store

1. Enumerate actual source, transformation, training and release producers and their identity authority. Protect receipt and manifest signing independently of the data and consuming process. Verify exact version identifiers, signer trust, content digests and parent links, including refused wrong or unapproved producer records.
2. Follow an approved release from its exact source through transformations and output to the stored record. Trace actual artifact and source identifiers in both directions. Include incomplete records, superseded source versions and affected-artifact recall.
3. Record access scope, retention and provenance integrity for the actual lineage and artifact stores. Retrieve historical records after a subsequent release and after an approved recovery, confirming old release, source and receipt references still resolve.
4. Include all governed training and publishing entry points and document scope and ownership of coverage gaps. Record only necessary sanitized artifact and record identifiers in evidence.

- [Kubernetes Persistent Volumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/persistent-volumes/)
