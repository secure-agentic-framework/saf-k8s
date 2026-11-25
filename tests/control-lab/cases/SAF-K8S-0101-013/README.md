# SAF-K8S-0101-013 — API server certificate rotation and validation

Run from the framework checkout with Python, OpenSSL, Kind, Docker, and kubectl.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0101-013 --docker-context desktop-linux
```

The runner creates a fresh Kubernetes v1.36.1 cluster. The test connects to the
HTTPS loopback endpoint in that run's kubeconfig and validates the serving
certificate's IP identity and chain against the public Kind CA. An unrelated
CA and a mismatched identity both cause certificate verification to fail.

The fixture gives the initial serving certificate a 20-minute lifetime.
The case reads the verified leaf expiry at the real clock, compares one-
and thirty-minute lead times, and renews while the leaf is still valid.
It runs `kubeadm certs renew apiserver` with the fixture's explicit renewal
validity policy and checks the new leaf exceeds the lead time. It temporarily moves the static manifest outside kubelet's watched
directory, confirms the original container stops, restores the manifest, then
checks that the replacement container becomes ready and serves a different
trusted certificate on the same endpoint. The two certificate rejection checks
also pass after renewal. Only verification booleans are logged. The lab keeps
the five-second observation of live certificate adoption before the restart
as a separate result so it can be interpreted in its time window.

The fixture exercises an expiry-based renewal decision and local signing.
An adopter verifies periodic scheduling, health gates, and all applicable
certificate roles separately.

## Adopter verification

1. Inventory every API-server replica, TLS termination point, certificate
   role, issuer, validity, identity and key usage. Include serving leaf,
   kubelet and etcd client identities, aggregation, and webhook paths.
   Record the approved trust anchors independently from endpoint identities.
2. Verify the scheduled renewal or upgrade mechanism, lead times and expiry
   monitoring, alert ownership, and what causes renewal or rollout to stop.
   Preserve the approved issuer policy and recovery procedure.
3. In a scoped rehearsal or approved change window, compare public leaf
   fingerprints and remaining lifetimes before and after renewal. Verify
   identity against the approved chain and confirm the actual peer uses the
   new certificate while the intended operations remain available. Check
   each replica, staged rollout, and any overlapping trust during CA change.
4. Record which provider paths expose lifecycle configuration or evidence
   and retain version-specific settings or attestation for the exact service.
   Mark unevidenced paths unverified. Store only redacted outcomes and
   public certificate identifiers in the evidence record.

- [Kubernetes v1.36 Certificate Management with kubeadm](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-certs/)
- [Kubernetes v1.36 kubeadm certs reference](https://v1-36.docs.kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-certs/)
- [Kubeadm renewal implementation at v1.36.1](https://github.com/kubernetes/kubernetes/tree/v1.36.1/cmd/kubeadm/app/phases/certs/renewal)

## Scheduled renewal decision

The live CronJob creates two Jobs. The first evaluates the public serving
leaf against a 60-second lead time and reports an out-of-window decision.
The second uses a 30-minute lead time and records a due request tied to the
same fingerprint and expiry. The runner confirms both Job owners and
effective Kubernetes authorization. The Job identity reads the exact input
ConfigMap and updates its named receipts. The case binds the CronJob-owned request to the live leaf fingerprint and
expiry. The scheduler identity is forbidden to update the approval record and
receives no node credentials. A distinct fixture approval identity can read
and patch only that named record. The supervisor checks the actual current
TLS leaf and accepts only the exact unexpired approved request. The native
command runs once. The recorded consumed request cannot trigger another
renewal. The fixture uses an impersonated test subject and the supervisor
acts as the local renewal broker.

The portable fixture exercises the precise Kubernetes approval and serving
transition. In a deployed implementation, verify approver authentication,
request and executor ownership, missed-run alerts, other TLS roles and
replica coverage. Companion fixtures verify the tested [etcd roles](../SAF-K8S-0102-014/README.md),
[kubelet serving leaf](../SAF-K8S-0101-012/README.md),
[webhook trust and leaf transition](../SAF-K8S-0605-008/README.md), and
[API aggregation backend serving leaf](../SAF-K8S-0404-002/README.md).
For an adopted implementation, map those paths to the real approved issuers,
serving identities, control plane and replica rollout plan.

## Serving certificate trust transition

After the existing renewal and trust checks, the case reuses the same
owned node and loopback API origin. It keeps the currently served renewed leaf
as the old state, creates a distinct temporary successor CA and an IP-SAN-correct
API-server leaf, then switches the actual API serving certificate pair and
restarts only that owned static Pod. Client-auth trust remains unchanged.

At the old-leaf and successor-leaf states, the case checks actual socket-served
SHA-256 fingerprints under old-only, overlap (old+new), and new-only trust. It
requires the expected x509 rejection for the untrusted root combinations. It
also GETs `/readyz` through each client trust context: old-only and overlap are
ready in the old state; overlap and new-only are ready in the successor state.
It restores the original renewed certificate pair in `finally`, restarts the
owned API server, checks the restored leaf/readiness, and removes its temporary
node files. Evidence contains only public fingerprints, trust/readiness
booleans, and statuses; it does not contain private keys, kubeconfig content,
or response bodies.

This comparison covers one API serving endpoint. SAF-K8S-0605-008
provides a separate example for webhook backend trust. Adopters must
verify their own approved CA bundle distribution, all real endpoints and
replicas, and the policy-defined trust removal and rollback gates.
