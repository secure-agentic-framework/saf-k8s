# SAF-K8S-0101-013 — API server certificate rotation and validation

Run from the lab root with Python, OpenSSL, Kind, Docker, and kubectl.

```sh
python3 lab.py test SAF-K8S-0101-013 --docker-context desktop-linux
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
