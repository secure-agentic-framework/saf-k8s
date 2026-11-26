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
