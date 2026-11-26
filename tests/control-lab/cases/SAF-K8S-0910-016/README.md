# SAF-K8S-0910-016 cross-cluster orchestration identity and rollover

This case retains the original three grouped checks, then adds a
fourth `rotation` check. It uses the adjacent pinned runtime and owned peer
helpers. Two distinct Kind APIs host source clients and a private mTLS gateway.
The original checks exercise baseline alternate-URI acceptance, enforced
identity and placement denials, an independent peer admission denial, and an
approved exact Deployment on the target API.

Expected check count is four total: the original `red`, `green`, and `positive`
phases remain, with one new grouped `rotation` phase.

## Secret-safe handling

The lab logger records stdin payloads verbatim. This candidate writes fixture
TLS Secret manifests and patches to mode-0600 files inside the existing mode-0700 temporary
directory, invokes `kubectl create -f <file>` or `kubectl patch --patch-file <file> -o name`, and unlinks the
file immediately. It does not read Secrets back or retain private keys,
certificate PEM, serials, dynamic UIDs, or fingerprint values. The original
positive gateway-event predicate also requires a nonempty authenticated peer
certificate and TLS 1.3.

## Fourth phase: requester certificate rollover

After the original positive check, the candidate exercises a second gateway
against the same peer API, namespace, ServiceAccount and exact Deployment
target. A temporary successor CA issues a new client leaf with the same
approved SPIFFE URI. The gateway's client trust comes from a case-owned Secret
loaded at startup and transitions through old-root-only, old-plus-new overlap,
and successor-root-only. The gateway restarts after each bundle change so its
TLS context consumes each trust state.

The old requester succeeds with old-only trust; the successor fails TLS before
HTTP. During overlap both leaves can submit only the fixed approved action.
Then the existing approved requester Secret is replaced with successor
material using a mode-0600 temporary manifest, and that same requester Pod name
is recreated. A separate retired-leaf comparator retains the old certificate.
With successor-only trust, the old comparator cannot complete TLS or persist
the target, while the restarted approved requester succeeds. The grouped
rotation check records only stable booleans. It also checks that the two public
leaf DER fingerprints differ and that all four accepted gateway events, read before each gateway restart, bind
TLS 1.3, the approved URI, and the exact peer action.

This is a local trust-bundle transition, not a SPIRE Workload API or cloud
workload identity federation test. It demonstrates the peer gateway's actual
certificate-chain behavior during a fixture root rollover and active requester
replacement. It does not demonstrate automated issuance, workload
attestation, remote bundle endpoint polling/distribution, or operator response
to compromise.

The fixture models the staged key transition described by the [SPIFFE
Federation specification](https://spiffe.io/docs/latest/spiffe-specs/spiffe_federation/)
and the consumption of updated SVID/bundle state described by the [SPIFFE
Workload API specification](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/).
It does not implement either SPIFFE endpoint. Secret update mechanics use
Kubernetes [`kubectl patch --patch-file`](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_patch/).
