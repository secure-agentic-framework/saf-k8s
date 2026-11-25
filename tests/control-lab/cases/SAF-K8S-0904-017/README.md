# SAF-K8S-0904-017 workflow definition signature admission

The case installs the upstream Argo Workflows v3.7.6 WorkflowTemplate CRD and
uses a fixture webhook on a fresh Kind cluster. The webhook validates
WorkflowTemplate creates and updates in the case namespace. It uses a pinned
Go image and standard-library Ed25519 verification. The runner needs no host
Go toolchain.

With the webhook inactive, Kubernetes admits the four fixed input definitions
in server dry-run. Once enabled, Kubernetes rejects the same unsigned,
modified, or untrusted inputs with the expected webhook reasons. A trusted
definition persists and its signed spec matches API storage. Changing that
spec while carrying forward the old signature is denied. The same change
persists with a fresh trusted signature.

The signature binds the object API version, kind, namespace, name, and complete
canonicalized spec. Private signing keys are generated in memory inside the
disposable fixture. The TLS key remains in the verifier pod's emptyDir. The
runner reads the public CA and fixed signed objects. Its stable assertions
exclude signatures, certificate times, and resource versions.

The CRD runs without the Argo controller. The case demonstrates the selected
Kubernetes admission boundary. Real controller execution, external metadata
dependencies, signing-key custody and rotation, broader admission scope, and
fleet rollout require separate evidence.

- [Kubernetes v1.36 dynamic admission control](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
- [Argo Workflows v3.7.6 WorkflowTemplate CRD](https://github.com/argoproj/argo-workflows/blob/v3.7.6/manifests/base/crds/minimal/argoproj.io_workflowtemplates.yaml)

## Verify an adopting implementation

Identify every production pipeline definition kind and admission path. Enforce signatures over the complete canonical spec and object identity. Verify signing-key custody, trusted signer rotation/revocation, freshness policy, controller execution path, and that mutation with an old signature is denied. The fixture tests Kubernetes admission for WorkflowTemplate objects with a local Ed25519 key and no Argo controller.
