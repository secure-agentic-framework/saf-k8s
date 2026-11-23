# SAF-K8S-0104-013 Kubernetes upgrade and recovery evidence

A disposable kubeadm control plane upgrades from Kubernetes 1.36.1 to 1.37.0, followed by its kubelet. The test verifies the ordered version change and a public marker retained across it. A separate Deployment rollback restores a failed workload rollout on the upgraded cluster. The selected transition skips etcd and certificate upgrades. Deployed control-plane recovery, availability, multi-node sequencing, add-on policy and provider procedures need separate evidence.
