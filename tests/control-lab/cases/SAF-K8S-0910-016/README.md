# SAF-K8S-0910-016 cross-cluster orchestration placement

`python3 tests/control-lab/lab.py test SAF-K8S-0910-016 --docker-context desktop-linux`

The case uses the adjacent pinned runtime and owned peer helpers. Two distinct
Kind APIs host a source client and a private mTLS gateway. Readiness checks use
the same authenticated Service path and confirm the gateway can reach its peer
Kubernetes API. The fixture signs short-lived client URI certificates locally.

The baseline accepts the alternate certificate from the same fixture CA and
places an inert Deployment. The target's actual Kubernetes API records the
Deployment and it becomes available before the test cleans up the baseline.
The enforced gateway refuses that alternate identity and refuses a different
placement requested by the approved identity. Peer-side admission independently
refuses the alternate name in server dry-run with the gateway's Kubernetes
identity. The approved identity places the exact Deployment and a gateway
decision record ties the verified URI to the accepted operation.

The raw receipt records both API identifiers and the target Deployment UID.
The normalized receipt retains outcomes and stable gateway observations.
Deployed workload identity federation, credential rotation and revocation,
routing, scheduling and fleet coverage require separate evidence.

## Fixture evidence handling

The lab logger records stdin payloads verbatim. The case writes the
three fixture TLS Secret manifests to mode-0600 files inside the existing
mode-0700 temporary directory, calls `kubectl create -f <file> -o name`, and
unlinks each manifest immediately. It does not read the Secret back or include
key/certificate material in its normalized evidence. The positive gateway
event predicate also requires a nonempty authenticated TLS peer certificate
and negotiated TLS 1.3, alongside the existing exact URI-to-placement event.
The case retains three grouped checks.
