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


## Pod certificate coverage in the v1.37 revision

The catalog revision `484ff64d07e3de8facdcc75775502bbfbe1e9434` also exercises
`podCertificate` projection in the same disposable cluster. The original
and first trust-bundle revision still exercise their trust-bundle assertions.
The new case builds an isolated fixture image in the selected local Docker
context. The original Pod stays Pending with its matching request unissued.
A dedicated ServiceAccount starts a signer scoped to the fixture namespace and
exact signer name. The same request receives a one-hour certificate. The same
Pod reads a valid key, an expected URI SAN and client-auth usage, then reloads
a distinct key and certificate chain when kubelet performs its normal refresh.
Only booleans are emitted from the credential verifier. All issued credentials
are disposable fixture material.

Allow up to 22 minutes after the signer starts for issuance and refresh. The
API requires a refresh hint at least ten minutes after certificate validity
starts. The fixture backdates validity by 30 seconds. Kubernetes adds up to
five minutes of jitter to the hint and processes refresh and projection
periodically. The run uses ordinary Kubernetes clocks and kubelet projection.
The test removes the fixture image tag and deletes the kind cluster.
Federation and peer authorization require separate evidence.

- [Kubernetes v1.37 Pod certificates and Cluster Trust Bundles](https://kubernetes.io/blog/2026/08/28/kubernetes-v1-37-pod-certificates-and-cluster-trust-bundles/)
- [Kubernetes v1.37.0 Pod certificate validation](https://github.com/kubernetes/kubernetes/blob/v1.37.0/pkg/apis/certificates/validation/validation.go)
- [Kubernetes v1.37.0 kubelet Pod certificate manager](https://github.com/kubernetes/kubernetes/blob/v1.37.0/pkg/kubelet/podcertificate/podcertificatemanager.go)
