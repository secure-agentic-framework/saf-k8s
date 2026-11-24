# SAF-K8S-0205-005 Verify eBPF program authorization and integrity

The case checks ordinary and init-container capability requests against
Restricted Pod Security, and reads the live restricted Job's effective UID
and capabilities. The Job verifies undeformed bytes with an ephemeral fixture
trust anchor, rejects altered bytes, and starts a disconnected Linux guest.
Inside the guest, the approved artifact's digest is checked again. A harmless
program is loaded and pinned without an attachment. The guest records the
loader result, its assigned program ID and tag, a separate inventory, and
the object's disappearance from inventory after unpinning.

```sh
python3 lab.py test SAF-K8S-0205-005 --docker-context desktop-linux
```

## Verify an adopter profile

1. Inventory actual versions, kernel features, effective loader identities,
   capability boundaries, host privilege, restrictions, and provider-owned
   components. Review Pod Security configuration, namespace exemptions and
   workload capabilities. Compare observed capability masks for the actual
   loader and representative governed workloads.
2. Identify where trust material and signatures are verified. Retain the
   approved program digest, source, expected signer, policy version, and
   the component's validation decision. In a disposable matching profile,
   use an authorized harmless known fixture to check an accepted object and
   rejected changed material. Identify the authorization check applying at
   the actual kernel load separately from the artifact integrity gate.
3. Reconcile scoped telemetry against inventory. Collect attributable
   attempted, refused and accepted loads, attachments and removals using the
   platform's approved audit or runtime sensor. Match loader identity, time,
   program ID and tag, intended attach point and action result. Compare with
   the current inventory and use an owned fixture to measure coverage, gaps
   and loss. Record provider evidence and explicit approvals for each path
   the operator cannot observe directly.
4. Repeat when the kernel, loader, trust policy, sensor, or attachment
   topology changes. Leave acceptance open when attribution, material
   provenance, visibility or a governed capability remains unresolved.

The test demonstrates a userspace integrity gate and the approved load
lifecycle of one unattached program. Kernel-level signature enforcement,
attachment and refused-load event coverage, and fleet monitor completeness
require evidence from the adopter's enabled mechanisms.

- [Kubernetes v1.36 Pod Security Standards](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Linux 6.12 BPF documentation](https://www.kernel.org/doc/html/v6.12/bpf/index.html)
- [bpftool v7.5 program inventory and load](https://raw.githubusercontent.com/libbpf/bpftool/v7.5.0/docs/bpftool-prog.rst)
