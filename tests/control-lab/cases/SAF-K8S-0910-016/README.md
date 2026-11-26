# SAF-K8S-0910-016 cross-cluster orchestration identity and rollover

This case retains the original three grouped checks and fourth `rotation`
check, then adds one grouped SPIRE issuer/federation check. It uses the
adjacent pinned runtime and owned peer helper. Two distinct Kind APIs host
source clients and a private mTLS gateway.
The original checks exercise baseline alternate-URI acceptance, enforced
identity and placement denials, an independent peer admission denial, and an
approved exact Deployment on the target API.

Expected check count is five total: the original `red`, `green`, and `positive`
phases, the existing grouped `rotation` phase, and one grouped `SPIRE-issued
federated mTLS identity` phase.

## Secret-safe handling

The lab logger records stdin payloads verbatim. The case writes fixture
TLS Secret manifests and patches to mode-0600 files inside the existing mode-0700 temporary
directory, invokes `kubectl create -f <file>` or `kubectl patch --patch-file <file> -o name`, and unlinks the
file immediately. It does not read Secrets back or retain private keys,
certificate PEM, serials, dynamic UIDs, or fingerprint values. The original
positive gateway-event predicate also requires a nonempty authenticated peer
certificate and TLS 1.3.

## Fourth phase: requester certificate rollover

After the original positive check, the case exercises a second gateway
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

## Fifth phase: actual SPIRE issuance and federation

The added stage runs SPIRE 1.16.0 server and agent images from the pinned
0504-006/007 fixtures in the same two owned Kind clusters. Each server gets a
separate in-memory signing key and trust domain. The agents use the native
Kubernetes PSAT and kubelet workload attestors; scoped registration entries
bind the exact source ServiceAccounts, Pod labels, the requesting `fetcher`
init container, and peer federation domain. The workload consumes the SVID
from its shared in-memory volume. SPIRE itself has fixture-infrastructure
privileges, including Pod and Node reads, an agent host PID view, and a
node-local socket mount. Workload eligibility also depends on governing
who may create Pods with the selected identities and labels.
Each side refreshes the other side's bundle through its
SPIRE HTTPS federation endpoint on the private Docker bridge. The case patches the existing
bootstrap ConfigMap and signals the owned Pod to refresh its mounted file
while the original signing process continues. Root bundle
material is public and transferred through temporary mode-0600 files; server
and workload private keys stay inside their SPIRE processes or Pod memory
volumes. Certificate-bearing command output is captured in memory and only
byte count, digest, and exit status are written to the command transcript.

The check observes two source SVIDs and one peer gateway SVID, compares their
SPIFFE IDs, current validity, bounded lifetime and foreign-root fingerprints,
then uses the peer SVID for the same actual mTLS gateway and exact Deployment
placement. A same-domain alternate source registration is refused before the
peer API changes. The SPIRE stage deletes and recreates only the same exact
fixture Deployment; the original native admission policy remains enabled. No
SVID PEM, private key, bearer token, or certificate bytes are retained in
evidence.

This is a local reference for SPIRE issuance, Kubernetes workload attestation,
two-way bundle exchange and one exact federated authorization path. It does
not establish production issuer custody, federation approval, cluster
availability, multi-node rollout, real scheduler behavior, policy governance,
or adopter identity/namespace mapping. Those remain adopter evidence.

The fetcher and the app run as the same non-root UID. The private key stays
owner-readable only in the shared memory-backed volume. Bounded init retries
allow the attested agent to sync entries before the app can start.
