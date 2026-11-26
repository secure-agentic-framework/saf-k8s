# Verify model quarantine and digest-bound release

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0905-044 --docker-context desktop-linux
```

The case compares unchecked admission with a restricted quarantine namespace.
It uses fixed synthetic scan results to check category completeness and subject
digest matching. Native admission and RBAC reject a mismatched digest and an
unauthorized release identity. An authorized release identity reads back the
exact digest allowed by those checks.

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
