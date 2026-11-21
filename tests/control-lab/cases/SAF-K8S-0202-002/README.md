# SAF-K8S-0202-002 — RuntimeClass assignment and handler selection

```sh
python3 lab.py test SAF-K8S-0202-002 --docker-context desktop-linux
```

The case configures a named containerd runc handler, a RuntimeClass with a
node selector, and a namespace-scoped ValidatingAdmissionPolicy. The same
protected Pod spec is admitted without a RuntimeClass in the baseline and
receives the exact policy denial after the binding is enabled. A permitted
Deployment then rolls out using the named class. Its Pod's admitted node
selector matches the selected node's handler label.

The baseline sandbox reaches Ready on the default profile without a state
directory beneath the custom handler's runc state root. For the permitted Pod,
look up the exact Ready sandbox ID by namespace and Pod name in CRI, then check
that this ID has a state directory under the configured handler's distinct
root. This observes actual runtime selection for the exact Pod. The alternate
handler uses the kind image's cgroupfs driver. The Deployment and all objects
are isolated to the cluster the runner deletes.

The fixture calls the same ordinary runc runtime in both arms. A stronger
sandbox boundary, workload-label governance, eligible production nodes,
gVisor/Kata selection, GPUs, and provider-specific isolation require separate
evidence.

- [Kubernetes v1.36 RuntimeClass](https://v1-36.docs.kubernetes.io/docs/concepts/containers/runtime-class/)
- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [containerd 2.3.1 runtime configuration](https://github.com/containerd/containerd/blob/v2.3.1/docs/cri/config.md#runtime-configuration)
- [containerd 2.3.1 runc shim option handling](https://github.com/containerd/containerd/blob/v2.3.1/cmd/containerd-shim-runc-v2/runc/container.go)
