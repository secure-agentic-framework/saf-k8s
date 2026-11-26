# SAF-K8S-0403-005 pipeline output filtering and secret delivery

Run `python3 tests/control-lab/lab.py test SAF-K8S-0403-005 --docker-context desktop-linux`
from the framework root.

The fixture checks Kubernetes client Secret diff masking with public,
noncredential marker records. The read-only comparison leaves the
persisted resource version unchanged.

A baseline Job writes the same public marker to its log, JSON artifact,
checkpoint and pipeline metadata. A redaction policy removes the marker
while preserving the expected fields. An independent read-only Pod
checks the three persisted files. An invalid policy stops before writing.

A separate Job receives a fixed inert input from a named, read-only
native Secret volume. It checks the expected input before running its
output filter. The unmounted comparison cannot produce output. The
read-only observer checks that the mounted Job's log and retained outputs
contain redacted values and no raw marker.

Pinned Trivy v0.76.2 scans both files and deterministic OCI layouts.
Separate promotion compares the exact approved scan digest and refuses
a flagged input, a scanner error or content changed after the scan. A
reader checks the retained bytes and absence of denied outputs.

For adoption, verify each actual credential authority and workload delivery
binding, alternate logs and status paths, real checkpoint and artifact
formats, image and tracker coverage, scanner rules, protected CI and
publication, and custody and retention of the evidence. Verify fixture
and deployment evidence without retaining credential values.

[Kubernetes Secret practices](https://v1-36.docs.kubernetes.io/docs/concepts/security/secrets-good-practices/) · [Trivy v0.76.2](https://github.com/aquasecurity/trivy/releases/tag/v0.76.2)
