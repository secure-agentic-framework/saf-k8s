# SAF-K8S-0402-010 — Kubernetes trust-bundle projection

A disposable Kubernetes v1.37 cluster creates test-only CA trust bundles using
the runner’s authorized identity. A synthetic Pod selects by signer and label.
It receives an empty trust file when only a bundle with a different label
exists. The exact expected CA appears after a matching bundle is created.
Updating that bundle replaces the CA in the running Pod without a restart.
The test verifies public certificate fingerprints in memory and retains the
match and count. Temporary test keys are discarded.

This verifies one implementation mechanism for trust delivery. Cross-cluster
federation needs authorized bundle exchange, workload identity issuance,
peer authentication and authorization, and workload use of the refreshed
trust anchors. Signer-specific admission and Pod certificate refresh have
their own evidence tasks.

```sh
python3 lab.py test SAF-K8S-0402-010 --docker-context desktop-linux
```

From the framework checkout use `python3 tests/control-lab/lab.py` with the
same arguments.

- [Kubernetes v1.37 Pod Certificates and Cluster Trust Bundles](https://kubernetes.io/blog/2026/08/28/kubernetes-v1-37-pod-certificates-and-cluster-trust-bundles/)
- [Kubernetes projected volumes](https://kubernetes.io/docs/concepts/storage/projected-volumes/#clustertrustbundle)
