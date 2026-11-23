# SAF-K8S-0403-003 Secret injection pattern tradeoffs

Run `python3 lab.py test SAF-K8S-0403-003` against the catalog revision in the
verified result. The disposable cluster exposes public markers via a regular
Secret directory, subPath, and an init-only copy. A selected workload class
requires the approved read-only directory mount. The same running Pod
demonstrates that only the directory updates when the source is replaced.

The test checks actual access and file mode for the declared fixture
container and absence of the mount from another container. Driver and
provider prerequisites, sidecar renewal, and actual application reload and
backend acceptance are covered separately.

- [Kubernetes Secret volume updates](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/secret/)
- [Secrets Store CSI Driver rotation](https://secrets-store-csi-driver.sigs.k8s.io/topics/secret-auto-rotation)
