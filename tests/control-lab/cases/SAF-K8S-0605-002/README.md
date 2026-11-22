# SAF-K8S-0605-002 — Kyverno admission policies

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0605-002 --docker-context desktop-linux
```

Kyverno v1.20 supports Kubernetes v1.34 through v1.37. Its supported CEL policy types replace the legacy `ClusterPolicy` and `Policy` execution path. The old API remains available for existing-object operations. The live API rejected creating the synthetic legacy `Policy` with the exact version-specific retirement message. The equivalent noncompliant Pod dry-run was admitted before the modern validation policy was installed. [Kyverno release support](https://kyverno.io/docs/installation/releases/), [Kyverno upgrade guidance](https://kyverno.io/docs/installation/upgrading/).

The case installs Kyverno v1.20.0 in a fresh Kubernetes v1.36.1 Kind cluster using the official Helm chart 3.10.0 and verifies the chart archive SHA-256. Helm and Kubernetes commands use the explicit disposable cluster kubeconfig and context. The case verifies that the four installed controllers use the chart's v1.20.0 image tags.

- A cluster-scoped GeneratingPolicy reacts to the exact case-owned namespace and label and creates an inert ConfigMap with the expected marker.
- The namespaced ValidatingPolicy in Audit mode admits a synthetic Pod without its required label. A live PolicyReport identifies the exact Pod, policy, source, failed rule, and violation message.
- Patching the same policy to Deny makes Kyverno reject the same Pod fixture with the exact webhook and violation. A compliant Pod and a comparison outside the policy namespace remain admissible.
- The namespaced MutatingPolicy adds a fixed label, non-root setting, and the `RuntimeDefault` seccomp profile before validation. The approved server-side dry-run response contains those fields.

The same run starts a disposable Distribution 3.0.0 registry on a loopback TLS
port and uses Cosign 3.1.4 to sign an inert OCI manifest with two separate
fixture keys. Each repository holds the same image bytes and digest. The
three artifact sets carry the approved key and required attestation, the
approved key alone, or the unrelated key and required attestation.

Before the `ImageValidatingPolicy` is installed, the API admits all three
server-side dry-run Pod requests. The policy accepts the approved image and
checks the attestation payload, rejects the missing predicate and unrelated
signer for their respective verification failures, and admits the same
unrelated-signer image outside its selected namespace. The registry container
and volume, private signing keys, and Kind cluster are removed.

The image checks require `openssl` to create a local TLS authority. A
selectorless Service routes the controller to the fixture registry, and the
chart mounts the registry CA during installation. Cosign and Kyverno use
keyed offline trust. Production signing identities, transparency logs, namespace
coverage, exceptions, generation policy and version-controlled promotion
require deployment evidence.

- [Kyverno installation](https://kyverno.io/docs/installation/installation/)
- [Kyverno supported policy types](https://kyverno.io/docs/policy-types/)
- [Kyverno v1.20 native Cosign verification](https://github.com/kyverno/kyverno/blob/v1.20.0/pkg/image/verifiers/ivpol/cosign/verifier.go)
- [Cosign v3.1.4 attestations](https://github.com/sigstore/cosign/blob/v3.1.4/doc/cosign_attest.md)
