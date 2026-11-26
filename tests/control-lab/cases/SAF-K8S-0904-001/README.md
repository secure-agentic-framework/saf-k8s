# SAF-K8S-0904-001 — Pipeline definition authorization and step isolation

The case uses the upstream Argo Workflows v3.7.6 minimal WorkflowTemplate CRD.
Server-side dry-runs first show a reviewer can write with a broad test binding.
The narrowed binding denies those same requests. The named author can create
and update the approved workflow definition. Its persisted fixture fields
supply a native Job step that runs non-root with a dedicated tokenless identity
and reads a bounded public marker through a read-only Secret volume.

The case preserves the explicit Job comparison and adds one Argo Workflows
v3.7.6 controller reconciliation. It applies the same case's approved
`saf-approved-template` through `workflowTemplateRef`, then checks the Workflow
UID owner reference, one successful Pod, effective scoped ServiceAccount,
non-root container security context, read-only public marker reference and absence
of a task-container ServiceAccount token mount. A separate executor identity
uses the narrowly named `workflowtaskresults` permissions required by the
controller fixture; its legacy token Secret is checked only as a Boolean and
its bytes are never read into retained evidence.

This extends the disposable reference to demonstrate that a pinned controller
can reconcile the exact persisted template. It does not prove repository
branch protections, pipeline approvals, deployed controller policy, external
secret stores, encryption, production identity management or other
orchestrators. Verify those independently in the adopting environment.

The vendored fixture is the [Argo Workflows v3.7.6 minimal WorkflowTemplate
CRD](https://raw.githubusercontent.com/argoproj/argo-workflows/v3.7.6/manifests/base/crds/minimal/argoproj.io_workflowtemplates.yaml).
Its accompanying upstream license is in `fixtures/ARGO-LICENSE.txt`.

The controller witness reuses the digest-pinned namespace-scoped controller-only
manifest from the paired SAF-K8S-0904-014 case. The manifest SHA-256 and both
Argo image index digests are checked before apply. The UI/server component is
excluded. The case has five checks. Run `python3 tests/control-lab/lab.py
test SAF-K8S-0904-001 --docker-context desktop-linux` from the framework
checkout to replay them.

## Scoped definition admission check

A server-side dry-run first admits the inert literal in the
`SAF_PUBLIC_MARKER` environment field of an owned WorkflowTemplate.
After the namespace-scoped ValidatingAdmissionPolicy becomes effective, the
same proposal receives the exact denial. The approved `secretKeyRef` form
passes and the harness independently checks the previously approved template
and the absence of the rejected proposal. The six-check case also verifies
native reconciliation of the original template.

For an adoption review, inventory every definition writer and credential input
field and confirm the configured policy handles each approved reference form.
Check runtime Secret custody, store permissions and evidence across the adopted
orchestrator and infrastructure. See [Kubernetes v1.36 admission policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/).
