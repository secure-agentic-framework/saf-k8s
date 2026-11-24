# SAF-K8S-0605-003 — Signed Kubewarden WASM admission

```sh
python3 lab.py test SAF-K8S-0605-003 --docker-context desktop-linux
```

From the SAF-K8S checkout, run `python3 tests/control-lab/lab.py` with the same arguments. The test uses Helm and curl on Linux or macOS with an AArch64 or x86-64 host. Kind starts a disposable Kubernetes v1.36.1 cluster. The runner checks three Helm chart archives and the platform's kwctl archive against their pinned SHA-256 values and pins the container images and policy module by OCI digest.

The baseline admits an inert ModelDeployment without its required label. Before deployment, kwctl accepts the module's signature under the Kubewarden GitHub owner requirement and rejects the identical digest under a mismatched owner requirement. The installed PolicyServer uses the trusted-owner configuration.

The namespaced AdmissionPolicy initially runs in monitor mode. The API admits the same request while the PolicyServer logs that the policy would deny it. After protect mode has taken effect, the API refuses the declaration and prevents removal of the required label from an existing compliant object. The compliant object's UID and label survive. A separate namespace remains outside the policy's scope.

The test exercises one released WASM module and one synthetic resource. Deployment coverage, signer custody, and operating rollout procedures require deployment evidence.

[Original control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0605-003.md) · [Monitor mode](https://docs.kubewarden.io/admission-controller/1.36/en/reference/monitor-mode.html) · [Signature verification](https://docs.kubewarden.io/admission-controller/1.36/en/howtos/security-hardening/secure-supply-chain.html)

The same command builds the owned label policy twice using Rust 1.92.0,
the committed Cargo lockfile, and the wasm32-wasip1 target. The pinned kwctl
sandbox verifies both native decisions. The fixture records the exact annotated
WASM digest, compiler version, and lockfile digest. Rustup provisions the pinned
compiler in the test directory. An existing exact toolchain can be supplied
through SAF_KUBEWARDEN_RUST_BIN. Bead saf-lab-0605-003.1 tracks the authorship and promotion evidence.

The authored policy is also promoted into a separate namespaced Kubewarden
protect policy. The lab signs the exact sandboxed OCI artifact in a disposable
TLS registry and confirms that the verified artifact contains the same WASM.
The separate PolicyServer uses the fixture public key and registry CA. It
admits the approved label and denies the missing label from the authored
digest. The signing key is removed at cleanup.
