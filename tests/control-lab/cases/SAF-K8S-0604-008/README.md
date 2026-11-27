# SAF-K8S-0604-008 runtime image component inventory

Run `python3 lab.py test SAF-K8S-0604-008` from the control-lab directory. One of the five checks reads the runtime component version and compares it with the bounded advisory fixture.

The added check executes the existing approved BusyBox fixture binary in the already-owned live inference Pod, reads only its self-reported version, and binds that observation to the Pod's already-observed runtime `imageID` and the exact pinned `BUSYBOX_IMAGE` reference. It compares against a reviewed, hash-pinned minimal extract of OSV's CVE-2023-42365 record, which lists BusyBox 1.36.1 as an exact affected version. The test image is BusyBox 1.37.0; no vulnerable package or vulnerability behavior is installed or exercised. The only positive affected-range comparator uses the inert version string `1.36.1` in memory.

The added result must establish:

- actual runtime version `1.37.0` is read from the exact inference Pod;
- the exact pinned image reference and observed image digest are present;
- the checked advisory fixture has the expected source ID/URL and the embedded SHA-256;
- the installed version is not listed in the advisory's exact affected-version set;
- a missing version or mismatched image identity classifies as `unknown`; and
- the inert exact `1.36.1` comparator is recognized as the listed affected version.

The comparison deliberately does not claim general semantic-version evaluation or that 1.37.0 is proven secure. It shows only that the reported version does not appear in this specific OSV record's exact-version extraction. The version is an observed image component, not a complete OS package database or software bill of materials. It does not inventory host driver files or libraries injected at runtime, prove advisory-feed freshness or scanner completeness, or establish public exposure. Those remain distinct adopter checks. Existing four assertions are unchanged; expected total is 5.

The advisory extract and its SHA-256 are stored in `busybox-advisory.json` and pinned in `case.py`. Primary source: [OSV CVE-2023-42365](https://osv.dev/vulnerability/CVE-2023-42365). The source record reports the CVE's CPE-extracted exact version 1.36.1; this candidate does not interpret a wider version range.

## Scratch purpose provenance supplement

The scratch `case.py` invokes the copied published `base_case.py` unchanged except for clarifying the existing fifth check's exact-version comparator label. It preserves the original five checks and adds one sixth check. The supplement creates an immutable, named ConfigMap with a fixed synthetic source URI/revision and bounded reviewed/valid timestamps. Its entries bind each case-owned Job or Deployment to the exact workload UID, Pod UID, image reference, observed runtime image ID, and controller-owner UID chain. It reads the ConfigMap back and checks the exact serialized bytes and SHA-256.

The sixth check exercises this fixed decision matrix: exact training and inference bindings classify to their fixture purposes; absent, expired, unknown-revision, or byte-tampered records are `unknown`; mismatched image, owner, exact image pin, or duplicate subject entries are `conflict`. Normalized output contains only these stable classifications/booleans; dynamic Kubernetes UIDs, resource version, record digest and full fixture record belong only in `purpose-provenance.raw.json`.

This is a synthetic comparator, not an independently authenticated release or organizational purpose approval. It creates the record from the already-running fixture identities, so it does not prove pre-deployment authorization or production classification. The five existing assertions still establish only their existing bounded case claims: fictional inventory correlation, private in-cluster reachability, and comparison against an exact-version OSV fixture. It does not perform scanning, test vulnerable behavior, validate a general version range, prove GPU/driver/library inventory, or establish public exposure. Organization-owned purpose sources, lifecycle/review authority, actual workload inventory, advisory freshness, and real exposure assessment remain adopter evidence.
