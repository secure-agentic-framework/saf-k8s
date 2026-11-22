# SAF-K8S-0201-013 — Kubelet client certificate rotation via TLS bootstrap

The case starts a disposable Kubernetes v1.36.1 cluster with two kubeadm
workers and a 150-second signing duration. Both workers must become Ready.
The rotation-disabled worker has to receive a bootstrap certificate and
write a lease during its initial validity. It then serves as the comparison
for the worker with native rotation enabled.

On the enabled worker, the test observes the bootstrap approver and signer
issuing a certificate for the exact owned node identity. It then observes an
approved, issued certificate from a new CSR requested by that node. The
certificate has the same subject and issuer, a different serial, and an
issuance interval consistent with signing before bootstrap expiry under the
configured signer lifetime. After both bootstrap certificates have expired,
the enabled worker must still be Ready and renew its lease. The disabled
worker must have neither an issued renewal nor a fresh lease.

The case parses public certificate metadata from API responses in memory.
It retains boolean observations and uses the stock kubeadm approver and
signer. Live deployment coverage, provider-managed rotation, external CA
schedules, monitoring, and control-plane bootstrap and renewal require
separate evidence.

From the repository root, run the case by ID. Its short-lived certificates
are special to the disposable test. Allow about three minutes for both
expiry observations.

```sh
python3 lab.py test SAF-K8S-0201-013 --docker-context desktop-linux
```

In the framework repository use `python3 tests/control-lab/lab.py` with the same
arguments. The runner prints the receipt and cluster cleanup outcome.

- [Pinned SAF-K8S control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0201-013.md)
- [Kubernetes v1.36 TLS bootstrapping](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/)
- [Kubernetes v1.36 certificate rotation](https://v1-36.docs.kubernetes.io/docs/tasks/tls/certificate-rotation/)
- [Kubernetes v1.36.1 signing expiration policy](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/controller/certificates/authority/policies.go)
