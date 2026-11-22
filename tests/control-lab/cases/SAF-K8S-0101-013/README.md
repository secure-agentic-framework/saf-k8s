# SAF-K8S-0101-013 — API server certificate rotation and validation

Run from the lab root with Python, OpenSSL, Kind, Docker, and kubectl.

```sh
python3 lab.py test SAF-K8S-0101-013 --docker-context desktop-linux
```

The runner creates a fresh Kubernetes v1.36.1 cluster. The test connects to the
HTTPS loopback endpoint in that run's kubeconfig and validates the serving
certificate's IP identity and chain against the public Kind CA. An unrelated
CA and a mismatched identity both cause certificate verification to fail.

The test runs `kubeadm certs renew apiserver` inside the owned control-plane
node. It temporarily moves the static manifest outside kubelet's watched
directory, confirms the original container stops, restores the manifest, then
checks that the replacement container becomes ready and serves a different
trusted certificate on the same endpoint. The two certificate rejection checks
also pass after renewal. Only verification booleans are logged. The lab keeps
the five-second observation of live certificate adoption before the restart
as a separate result so it can be interpreted in its time window.

The fixture exercises manual kubeadm renewal with the cluster's local CA.
Deployment verification covers automated scheduling before expiry, external
issuers, real client and proxy endpoints, high-availability rollout, and API
server connections to etcd, kubelets, aggregated APIs, and webhooks.

- [Kubernetes v1.36 Certificate Management with kubeadm](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-certs/)
- [Kubernetes v1.36 kubeadm certs reference](https://v1-36.docs.kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-certs/)
- [Kubeadm renewal implementation at v1.36.1](https://github.com/kubernetes/kubernetes/tree/v1.36.1/cmd/kubeadm/app/phases/certs/renewal)
