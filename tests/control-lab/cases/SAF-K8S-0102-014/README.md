# SAF-K8S-0102-014 etcd certificate renewal

Run the case with `python3 tests/control-lab/lab.py test SAF-K8S-0102-014 --docker-context desktop-linux` from the framework root or use `lab.py` in the lab checkout.

The disposable Kubernetes v1.36.1 control plane uses kubeadm-managed local
PKI and stacked etcd. Before recycling any static Pod, the case uses actual
partial renewal to leave the peer certificate unchanged, then detects the
omitted class and renews it. It checks all three public certificate receipts,
restarts the two affected static Pods, reads the active etcd certificates,
and checks Kubernetes storage read and write continuity. Private key bytes
stay inside the disposable node.

Scheduled automation, multi-member rollout, failed rotation recovery,
externally managed issuance and deployment policy remain unverified here.

- [Kubernetes v1.36 kubeadm certificate management](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-certs/)
- [etcd transport security](https://etcd.io/docs/v3.6/op-guide/security/)
