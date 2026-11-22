# SAF-K8S-0201-014 — Kubelet serving certificate trust and expiry

This test configures a disposable Kubernetes v1.36.1 control-plane kubelet to
serve a certificate issued by an isolated test CA. The legitimate TLS
handshake verifies both CA trust and the actual node’s DNS name. It confirms
the peer presents the exact configured leaf and that it remains valid for at
least 24 hours. The one-day floor is a test threshold.

The same public leaf is checked offline against an unrelated CA, an unrelated
DNS name, and a validation time beyond expiry. Each check must fail for its
specific reason. Test keys and certificate material are generated under the
runner's temporary directory and removed at cleanup.

This demonstrates a CA-issued serving certificate and client validation.
The Kubernetes serving-CSR path, production renewal and expiry monitoring,
provider-managed TLS and deployment-wide enforcement need separate evidence.

```sh
python3 lab.py test SAF-K8S-0201-014 --docker-context desktop-linux
```

From the framework checkout use `python3 tests/control-lab/lab.py` with the
same arguments. The case uses OpenSSL on the host and inside the kind node.

- [Kubelet v1.36.1 TLS configuration fields](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/kubelet/config/v1beta1/types.go)
- [Kubernetes v1.36 kubelet-serving signer policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#kubernetes-signers)
