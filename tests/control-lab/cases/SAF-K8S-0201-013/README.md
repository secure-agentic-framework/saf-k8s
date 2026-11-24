# SAF-K8S-0201-013 Kubelet client certificate lifecycle

From the framework root, run:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0201-013 --docker-context desktop-linux
```

The disposable Kubernetes v1.36.1 case observes native kubeadm TLS bootstrap
and client certificate rotation on an enabled worker, with a disabled worker
for comparison. It verifies the issued public certificates against the API
server's configured client CA and for the client authentication purpose.
Historical certificates are checked inside their validity interval, with
expiry recorded separately. Issuance and renewal are attributed to the same
node through the request subject and authenticated renewal identity.

The enabled worker receives a distinct replacement before expiry, reports
the expected native certificate TTL, and advances its node Lease after the
initial certificates expire. The disabled worker enrolls initially, then has
no replacement and a stale Lease. The first control-plane
rehearsal uses kubeadm's initial kubelet provisioning phase to create a
short-lived seed in a protected, disposable directory. The running kubelet
uses that directory and reports the seed's TTL. It installs the exact new
native, approved client certificate before seed expiry, and the same node
writes a fresh Lease after expiry. The case restores the original service
paths and deletes the temporary seed. The 150-second lifetime is reserved
for this disposable test.

## Verify your implementation

- Inventory all worker and control-plane provisioning paths, approvers,
  issuers, node identities and effective API-server client trust. Distinguish
  bootstrap token enrollment from approved seeded credentials on an initial
  control plane. Check that bootstrap authorization is limited to the intended
  node provisioning workflow and that the effective signer accepts the
  expected client usages and subject.
- Verify the effective `rotateCertificates` setting where native rotation
  applies. Confirm observed issuance, approval, signed identity, validity
  interval, and activation of a replacement before expiry. Track continued
  authenticated node requests after the first certificate expires.
- Observe certificate expiry, pending, denied and failed CSRs, issuer
  availability and renewal errors. Identify the current owner, lead time,
  alert route, escalation and recovery. Rehearse alert delivery and response
  in a representative staging environment. The versioned native metrics are
  alpha. Interpret missing or infinite TTL with CSR, issuer, and certificate
  inventory evidence. Use Node Leases as an additional liveness signal.
- For external CA and provider-operated paths, record the relevant nodes,
  service and version, effective API-server trust, authorized issuance and
  replacement records, and actual monitoring coverage. Track unresolved
  approval or trust gaps.
- Retain approved issuance and audit metadata independently of the live CSR
  view, which Kubernetes garbage-collects. Use public certificate metadata,
  expiry and Lease observations, and keep private credentials in their
  protected stores.

- [Kubernetes v1.36 TLS bootstrapping](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/)
- [Kubernetes v1.36 certificate rotation](https://v1-36.docs.kubernetes.io/docs/tasks/tls/certificate-rotation/)
- [Kubernetes v1.36 CSR and signer policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/)
- [Kubernetes v1.36 metrics](https://v1-36.docs.kubernetes.io/docs/reference/instrumentation/metrics/)
