# Verify model quarantine and digest-bound release

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0905-044 --docker-context desktop-linux
```

The case compares unchecked admission with a restricted quarantine namespace.
It uses fixed synthetic scan results to check category completeness and subject
digest matching. Native admission and RBAC reject a mismatched digest and an
unauthorized release identity. An authorized release identity reads back the
exact digest allowed by those checks.

A separate tokenless Job reads the exact inert model-like JSON bytes. It
checks a bounded format and marker rule and emits the exact digest. A release
with a different artifact digest is refused, and the authorized release is
read back with the observed scanner digest. The artifact and marker checks
illustrate the handoff for a known format.

The bundled kindnet CNI enforces default-deny egress from a quarantine Pod to
two fixture HTTP endpoints. A temporary policy allows only one endpoint on
TCP/8080. An independent Pod remains able to reach the other endpoint, and
removing the exception restores denial. The policy presence assertion and the
traffic observations are recorded separately.

For a deployment, identify the CNI and test the quarantine paths with its
actual selectors and exception rules. Retain the scanner identity, version,
policy and authenticated result for the input digest. Verify who can approve
release, how the scanner result is linked to that approval, and how both are
retained for review. The HTTP endpoints in the reference case serve fixed
markers, and the scan decisions are supplied by the fixture.

## Release metadata update guard

The case creates a ServiceAccount and a namespaced Role whose
`patch` permission is limited by `resourceNames` to the single inert release Pod.
It first adds an unrelated fixture annotation to that Pod and requires the update to
succeed. It then attempts to replace the recorded scanned-artifact digest with a fixed
nonmatching value and requires the existing ValidatingAdmissionPolicy to reject the
update. An independent API read checks the same Pod UID, original model and artifact
digests, clean/approved labels, and the accepted metadata annotation. This is an
admission update-path check only; scanner effectiveness, approval provenance and
production release workflow remain deployment evidence.

## Offline YARA-X marker scan

The restricted quarantine Job runs YARA-X 1.24.0. The host verifies the
pinned wheel size and digest and builds the fixture image offline. An
immutable ConfigMap supplies two inert JSON documents and the fixed test
rule. The clean document produces no match. The second contains a harmless
excluded marker and matches the rule. Kubernetes admission accepts the
exact clean digest through the governed approval path and refuses the
actual flagged digest in server dry-run. The evidence retains both artifact
digests, the rule digest and match name, and the pinned scanner identity.

For deployment, verify the approved scanner and signature sources, update
process, supported formats, dangerous-content policy, scoped approvers,
and representative coverage using approved test artifacts.

[YARA-X Python API](https://virustotal.github.io/yara-x/docs/api/python/)
