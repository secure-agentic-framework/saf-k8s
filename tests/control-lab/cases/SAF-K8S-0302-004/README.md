# SAF-K8S-0302-004 — Host namespace admission

## Case scope

The v1.36.1 fixture independently submits `hostPID`, `hostIPC`, and
`hostNetwork` requests to an unenforced namespace and namespaces pinned to
Pod Security Admission Baseline and Restricted. Every request containing any
host namespace field uses Kubernetes server-side dry-run through the single
`server_dry_run` helper. No host-namespace Pod is persisted or run, and the
case never inspects host state or sensitive endpoints. One ordinary isolated
Pod is persisted in the Baseline namespace and reaches Ready.

The exception namespace has its own namespace-scoped `create pods` Role and a
RoleBinding for the synthetic submitter. That binding is the test's explicit
owner approval grant. A separate ValidatingAdmissionPolicy constrains the
request to the exact synthetic hostNetwork Pod shape, name, namespace,
identity, and configuration. The case checks effective `can-i` authorization,
proves the approved request is admitted as a dry-run, deletes the test grant,
then verifies the same hostNetwork dry-run is denied. It also verifies that
the grant withdrawal leaves an ordinary isolated request admissible under
Restricted. This is a namespaced test lifecycle, not a production approval
system or an expiry simulation.

Raw safe API responses and RBAC observations are written to `lab.evidence` as
`*.raw.json`. `lab.check` names, pass/fail predicates, and detail strings are
stable across runs; cluster-specific API messages remain in the raw evidence.
Evidence contains only synthetic manifests and admission/authorization
responses. Review it before exporting from an adopter environment.

## Adoption evidence

Use read-only inspection and benign server-side dry-runs in an adopter-approved
environment. Never create or run a host-namespace Pod to demonstrate a control.
Record the cluster/API version, collection time, policy revision, evidence
owner, scope, and exclusions. Redact credentials and sensitive workload data.

1. **Expected rule.** Check the Kubernetes version's matching Pod Security
   Standards. Baseline and Restricted disallow `hostPID`, `hostIPC`, and
   `hostNetwork`; that statement alone does not prove the cluster enforces it.
2. **Effective scope.** Collect read-only evidence of Pod Security Admission
   availability and the enforce level/version on each in-scope workload
   namespace. Identify exclusions. Record the relevant policy and binding (or
   webhook) selectors, failure behavior, CREATE/UPDATE coverage, and who can
   change namespace labels, policies, bindings, and exception selectors.
   Preserve relevant RBAC and audit records.
3. **Authenticated approval and withdrawal.** For every real exception, retain
   the authenticated approval event and identity, approving owner, workload
   owner, business need, exact namespace/workload/host fields, allowed shape,
   compensating controls, start and expiry/review time, and audit trail. Verify
   the authenticated approval identity is the one authorized by the live
   policy and RBAC. Confirm withdrawal or expiry removes the effective grant:
   inspect the resulting policy/selector/RBAC state and, where authorized,
   submit the same benign host-namespace request with server-side dry-run and
   confirm denial. A recorded expiry date is not proof of automatic expiry;
   collect the controller/audit evidence showing the grant was actually
   withdrawn. Do not use the synthetic fixture identity or its grant as
   adopter approval evidence.
4. **Compensating controls.** Verify the deployed exception against its
   approved shape using read-only workload and policy inspection. Gather
   evidence for each claimed control, such as least-privilege service identity
   and token mounting, filesystem and volume restrictions, process/host access
   boundaries, monitoring, and network restrictions. For `hostNetwork`, use
   the adopter's CNI/vendor documentation plus safe configuration inspection
   or an approved benign observation to establish whether and how NetworkPolicy
   applies to that workload. Behavior varies by implementation and topology;
   do not count NetworkPolicy as compensation until its effective behavior is
   established. Do not probe host interfaces, metadata services, or sensitive
   endpoints.
5. **Separate outcomes.** Report (a) the expected versioned rule, (b) actual
   admission responses and configuration in the named environment, and
   (c) adoption governance and effective compensation. If authenticated
   approval, expiry/withdrawal, namespace coverage, or a compensating control
   cannot be evidenced, mark that item **unverified**, not passed. Admission
   dry-run demonstrates an API decision only; it does not prove runtime
   containment or remediation of existing Pods.

Useful versioned references:

- [Kubernetes v1.36 Pod Security Standards](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes Validating Admission Policy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes NetworkPolicy and hostNetwork](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/#networkpolicy-and-hostnetwork-pods)
