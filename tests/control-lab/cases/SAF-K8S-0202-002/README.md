# SAF-K8S-0202-002 — RuntimeClass and runtime selection

```sh
python3 lab.py test SAF-K8S-0202-002 --docker-context desktop-linux
```

The Kind case first demonstrates explicit selection of a named runc handler
and its exact sandbox state. It also installs the official gVisor
`release-20261116.0` package inside the disposable node. The harness verifies
the architecture-specific digest and transfers only the reviewed runtime,
containerd shim and required sidecars. The CRI handler uses the systrap
platform.

A namespace label set by the operator governs the gVisor Pod admission
example. Before the binding, a marker specification without a runtime class
is admitted on server dry-run. The same specification is denied after the
binding. The admitted non-root Pod with the approved RuntimeClass selects
the eligible node and emits its marker. Its exact Ready CRI sandbox ID is
matched against live runsc state and the installed gVisor shim executable.

## Verify an adopter deployment

1. Inventory node images, runtime and shim versions, configured handlers,
   architecture and relevant kernel or virtualization support per node
   pool. Verify eligibility labels reflect attested runtime readiness.
   Retain the effective handler configuration and source revision.
2. Define risk-based workload assignments and approved exceptions.
   Protect namespace classification, runtime class definitions and policy
   changes. Verify required and disallowed assignments across the workload
   controllers in scope. Record who controls eligibility and how stale or
   absent node readiness is handled.
3. Run a representative benign workload with the approved class in staging.
   Compare the Pod's admitted class and assigned node with the exact CRI
   sandbox and its runtime or VM identity. Retain marker status, workload
   privileges and relevant compatibility results. Assess isolation against
   the declared threat model.
4. For Kata, verify the actual guest, shim and platform requirements. For an
   accelerator profile, use the supported driver, firmware, device plugin
   and runtime combination, and retain real allocation and a benign
   accelerator result. The local gVisor fixture uses a CPU workload.
5. For provider-operated or homogeneous-runtime cases, retain the applicable
   service/tier evidence, risk basis, exception owner and review date.

- [Kubernetes v1.36 RuntimeClass](https://v1-36.docs.kubernetes.io/docs/concepts/containers/runtime-class/)
- [gVisor containerd configuration](https://gvisor.dev/docs/user_guide/containerd/configuration/)
- [gVisor releases](https://gvisor.dev/release/)
- [gVisor GPU guidance](https://gvisor.dev/docs/user_guide/gpu/)
