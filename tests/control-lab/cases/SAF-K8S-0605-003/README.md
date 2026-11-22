# SAF-K8S-0605-003 — Signed Kubewarden WASM admission

```sh
python3 lab.py test SAF-K8S-0605-003 --docker-context desktop-linux
```

From the SAF-K8S checkout, run `python3 tests/control-lab/lab.py` with the same arguments. The test uses Helm and curl on Linux or macOS with an AArch64 or x86-64 host. Kind starts a disposable Kubernetes v1.36.1 cluster. The runner checks three Helm chart archives and the platform's kwctl archive against their pinned SHA-256 values and pins the container images and policy module by OCI digest.

The baseline admits an inert ModelDeployment without its required label. Before deployment, kwctl accepts the module's signature under the Kubewarden GitHub owner requirement and rejects the identical digest under a mismatched owner requirement. The installed PolicyServer uses the trusted-owner configuration.

The namespaced AdmissionPolicy initially runs in monitor mode. The API admits the same request while the PolicyServer logs that the policy would deny it. After protect mode has taken effect, the API refuses the declaration and prevents removal of the required label from an existing compliant object. The compliant object's UID and label survive. A separate namespace remains outside the policy's scope.

The test exercises one released WASM module and one synthetic resource. Custom module authorship and sandbox pretesting, broader deployment coverage, and production rollout procedures require separate evidence.

[Original control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0605-003.md) · [Monitor mode](https://docs.kubewarden.io/admission-controller/1.36/en/reference/monitor-mode.html) · [Signature verification](https://docs.kubewarden.io/admission-controller/1.36/en/howtos/security-hardening/secure-supply-chain.html)
