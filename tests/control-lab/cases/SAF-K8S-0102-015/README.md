# SAF-K8S-0102-015 etcd certificate recovery drill

From the framework root, run `python3 tests/control-lab/lab.py test SAF-K8S-0102-015 --docker-context desktop-linux`.

The case runs on one disposable kubeadm-managed Kind control plane. It
checks verified etcd health, stages a mismatched leaf pair in the node,
and observes the explicit etcd TLS error and lost health. It restores the
original matching pair, confirms etcd health and Kubernetes readiness,
and checks both an existing object and a new API write. The original
key stays on the disposable node throughout the rehearsal.

The case measures one local restoration. Production quorum, issuer
transitions, outage tolerance, monitoring and repeated procedure rehearsal
require deployed evidence.

- [Kubernetes v1.36 kubeadm certificate management](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-certs/)
- [etcd transport security](https://etcd.io/docs/v3.6/op-guide/security/)
