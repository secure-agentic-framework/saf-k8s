# SAF-K8S-0605-002 — Kyverno admission policies

```sh
python3 lab.py test SAF-K8S-0605-002 --docker-context desktop-linux
```

Kyverno v1.20 supports Kubernetes v1.34 through v1.37. Its supported CEL policy types replace the legacy `ClusterPolicy` and `Policy` execution path. The old API remains available for existing-object operations. The live API rejected creating the synthetic legacy `Policy` with the exact version-specific retirement message. The equivalent noncompliant Pod dry-run was admitted before the modern validation policy was installed. [Kyverno release support](https://kyverno.io/docs/installation/releases/), [Kyverno upgrade guidance](https://kyverno.io/docs/installation/upgrading/).

The case installs Kyverno v1.20.0 in a fresh Kubernetes v1.36.1 Kind cluster using the official Helm chart 3.10.0 and verifies the chart archive SHA-256. Helm and Kubernetes commands use the explicit disposable cluster kubeconfig and context. The case verifies that the four installed controllers use the chart's v1.20.0 image tags.

- A cluster-scoped GeneratingPolicy reacts to the exact case-owned namespace and label and creates an inert ConfigMap with the expected marker.
- The namespaced ValidatingPolicy in Audit mode admits a synthetic Pod without its required label. A live PolicyReport identifies the exact Pod, policy, source, failed rule, and violation message.
- Patching the same policy to Deny makes Kyverno reject the same Pod fixture with the exact webhook and violation. A compliant Pod and a comparison outside the policy namespace remain admissible.
- The namespaced MutatingPolicy adds a fixed label, non-root setting, and the `RuntimeDefault` seccomp profile before validation. The approved server-side dry-run response contains those fields.

All ten assertions matched between the original and revised catalog receipts in `evidence/SAF-K8S-0605-002/20261122T093119Z-a03f1ae8/result.json` and `evidence/SAF-K8S-0605-002/20261122T093119Z-e65bb01b/result.json`. Image signature and attestation admission is a separate executable follow-up. Actual namespace coverage, exception governance, production generation policy and version-controlled policy promotion require deployment evidence.

- [Kyverno installation](https://kyverno.io/docs/installation/installation/)
- [Kyverno supported policy types](https://kyverno.io/docs/policy-types/)
