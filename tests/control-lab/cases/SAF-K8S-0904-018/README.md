# SAF-K8S-0904-018 — Governed immutable workflow rollback

This separate draft preserves the earlier `case/` version unchanged. The existing runner loads cases from `cases/SAF-K8S-0904-018/`; the supervising reviewer must stage these `governed-case/` files there before invoking it. The runner creates a fresh Kind v1.36.1 cluster using its digest-pinned default node image:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0904-018 --docker-context desktop-linux
```

The case uses the runner's `lab.create`, `lab.kubectl`, `lab.block`, `lab.check`, and `lab.evidence` interfaces. It creates only case-owned namespaced API objects; it does not create Pods or execute workflows. The three fixed workflow bodies are inert strings with checked SHA-256 values.

## Version controls

The case binds a namespaced ServiceAccount to a broad temporary ConfigMap Role, confirms that this same API identity can patch the mutable v1 fixture, and sends a server-side dry-run delete. The dry-run must be allowed while the object UID and tampered content remain present. The case restores the exact fixture content, marks v1 immutable, and repeats the identical patch while the broad Role still grants writes; the API must reject it for immutability. It creates immutable v2 and later narrows the Role so the operator can read/list and create ConfigMaps and can patch/update only the active pointer. Under the narrowed Role, patch and delete attempts against v1 must be forbidden and create using its still occupied name must return AlreadyExists. This keeps the original immutability/RBAC checks and measures pre-policy deletion capability without persisting a delete.

## Admission approval point

The administrator-created parameter is an immutable `core/v1 ConfigMap` named `saf-workflow-approval-v1` in `saf-test`, separate from the operator-writable active pointer. Its data binds a fixed approved change ID and transition to the API-observed v2 source name, SHA-256, and UID, and v1 target name, SHA-256, and UID. The requesting operator is explicitly read-tested against this object. After RBAC is narrowed, patch, replace, and delete attempts against the parameter must all be forbidden, and the object must still be present and unchanged.

Before creating the policy and binding, the case submits a server-side dry-run patch that has the correct v2 source and v1 target identity/digest but an unapproved change ID. It must be admitted, and an API read must show that pointer data, resourceVersion, and UID did not change. It then creates an `admissionregistration.k8s.io/v1` `ValidatingAdmissionPolicy` and `ValidatingAdmissionPolicyBinding`. The policy uses `failurePolicy: Fail`, a `Deny` action, a required `paramRef` with `parameterNotFoundAction: Deny`, `paramKind` `v1/ConfigMap`, and a CEL match condition limited to UPDATE requests in `saf-test` for `saf-workflow-active`.

The identical mismatched patch is submitted again with the same active-pointer `resourceVersion`. It must be denied with the policy's fixed Forbidden reason and exact validation message. An unrelated error, CEL warning, missing type-check status, or other failure blocks the case before it is treated as evidence of enforcement. The matching patch then supplies the current pointer `resourceVersion` as Kubernetes' optimistic concurrency precondition. The policy requires the parameter itself to be marked immutable, checks the old object source name/SHA/UID, and compares the requested target name/SHA/UID/change ID with that parameter. API readback must show the active pointer refers to the existing immutable v1 object and its original digest and UID.

`ValidatingAdmissionPolicy` CEL cannot read `metadata.resourceVersion`; the compare-and-swap precondition is provided by the Kubernetes API update using the caller-supplied `resourceVersion`, while admission checks the expected old pointer fields. Kubernetes documents that stale update resourceVersions produce a conflict. The exact resourceVersion values are retained only in `governed-rollback.raw.json`, not in `checks[*].observed`.

## Evidence boundaries

`checks[*].observed` contains only fixed claim booleans and does not include run-specific UIDs, resourceVersions, server error text, or signatures. Dynamic API objects, dry-run responses, policy status, and error text are retained separately in raw run evidence for supervisor inspection. The `lab.check` helper prints observations and stores them in `result.json`; the case follows that existing interface.

The approval parameter is synthetic test data, not proof of an organization’s approval authority, authentic approver identity, separation of duties, signing, or durable audit. The CEL policy compares the request to this parameter; it does not dereference another ConfigMap. The fixture runner verifies the retained v1 object and content before approval parameter creation and after rollback. A cluster administrator can alter policy, binding, parameter, RBAC, or the objects outside the fixture operator role. The case does not prove production storage retention, namespace governance, API audit retention, repository-owner controls, Argo/Kubeflow integration, workflow execution using the approved bytes, or recovery across clusters. ConfigMap immutability still permits deletion and recreation; the namespaced operator is separately denied delete only after the Role is narrowed. These privileged and persistence paths require production evidence.

The retained lab and independent framework replay each passed six checks on separate Kubernetes v1.36.1 Kind clusters. [Verified receipt](../../verified/SAF-K8S-0904-018.json).

## Primary references

- [Kubernetes v1.36 Validating Admission Policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/) documents native CEL admission, bindings, parameter resources including core types, per-namespace parameter references, `parameterNotFoundAction`, and parameter read authorization.
- [Kubernetes v1.36 ValidatingAdmissionPolicy API](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/admissionregistration/validating-admission-policy-v1/) documents the v1 schema, available CEL request variables, `Forbidden` reason, and metadata CEL field access limits.
- [Kubernetes v1.36 admission controllers](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/admission-controllers/) lists ValidatingAdmissionPolicy enabled by default in v1.36 and identifies it as API-server native admission.
- [Kubernetes v1.36 ConfigMap API](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/core/config-map-v1/) and [ConfigMap guide](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/configmap/) document immutable data semantics and the delete/recreate exception.
- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/) documents namespaced Roles and RoleBindings and the inability to restrict top-level create by object name.
- [Kubernetes v1.36 object names and UIDs](https://v1-36.docs.kubernetes.io/docs/concepts/overview/working-with-objects/names/) documents name reuse after deletion and UID identity.
- [Kubernetes v1.36 API concepts](https://v1-36.docs.kubernetes.io/docs/reference/using-api/api-concepts/) documents update/patch resourceVersion preconditions, lost-update detection, stale-version conflicts, and server dry-run authorization.
- [kubectl v1.36 options](https://v1-36.docs.kubernetes.io/docs/reference/kubectl/generated/kubectl_options/) documents `--as` impersonation; the lab runner credential must be authorized to impersonate the fixture operator.

## Verify actual definition history and rollback

1. Inventory the workflow engine, immutable definition store, actual
   version/identity keys, approval authority, retention and recovery
   objectives, and every actor with permission to replace or delete
   versions and change active references.
2. Choose two inert versions in an approved environment. Record their
   protected identities and digests. Use an ordinary governed actor to
   compare a denied edit/delete and accepted read. Verify how administrators
   and retained history are controlled independently.
3. Compare an unapproved or stale rollback with an approved transition
   for the exact current and retained target identifiers. Bind the
   controlling authority, change identifier and evidence to that
   decision. Read back the resulting active version, original target
   identity and digest.
4. In the actual workflow engine, verify a controlled inert execution
   consumes the selected preserved definition and emits its matching
   version receipt. Capture the authorization and execution evidence
   from separate components, including cleanup and recovery timing.
