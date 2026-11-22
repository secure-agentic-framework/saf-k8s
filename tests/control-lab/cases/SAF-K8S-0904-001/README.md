# SAF-K8S-0904-001 — Pipeline definition authorization and step isolation

The case uses the upstream Argo Workflows v3.7.6 minimal WorkflowTemplate CRD.
Server-side dry-runs first show a reviewer can write with a broad test binding.
The narrowed binding denies those same requests. The named author can create
and update the approved workflow definition. Its persisted fixture fields
supply a native Job step that runs non-root with a dedicated tokenless identity
and consumes a public marker through a read-only Secret volume.

The test installs the WorkflowTemplate API and runs the Job explicitly. Argo
controller reconciliation, external secret stores, encryption, production
identity management, and the other orchestrators need separate evidence.

The vendored fixture is the [Argo Workflows v3.7.6 minimal WorkflowTemplate
CRD](https://raw.githubusercontent.com/argoproj/argo-workflows/v3.7.6/manifests/base/crds/minimal/argoproj.io_workflowtemplates.yaml).
Its accompanying upstream license is in `fixtures/ARGO-LICENSE.txt`.
