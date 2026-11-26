# SAF-K8S-0606-022 — Verify manifest signatures at admission

```sh
python3 lab.py test SAF-K8S-0606-022 --docker-context desktop-linux
```

From the SAF-K8S framework checkout, use `python3 tests/control-lab/lab.py`.
The case requires host Go and a Docker-backed Kind cluster. It builds a
standard-library HTTPS webhook and generates ephemeral signing and TLS keys
for each run. The signing keys stay in memory. The TLS key is written only
into the runner's temporary directory, imported into the disposable cluster,
and removed from the host. Evidence retains only public certificates,
signatures, signed preimages, and relevant admission decisions.

Before registering the webhook the API stores the unsigned fixture. After
registration the webhook rejects absent signatures, an otherwise valid
signature from an unapproved signer, and changed binary data. It accepts
the unchanged authorized fixture. It also rejects an update with an old
signature, leaves the stored resource unchanged, and accepts the exact
payload after re-signing.

The signed JSON includes API version, kind, name, namespace, labels, data,
binary data, and the optional immutable field. Server-managed metadata,
other metadata, and original file formatting are outside the projection.
Kubernetes sends the API object in a JSON AdmissionReview. This test
exercises the selected ConfigMap CREATE and UPDATE paths. The wider catalog
obligations include other kinds and namespaces, policy ownership, signer
governance, and coverage of actual GitOps and deployment automation.

See [the pinned control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0606-022.md),
[Kubernetes v1.36 validating webhooks](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/),
and the [v1.36.1 admission types](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/api/admission/v1/types.go).

## Typed Pod dry-run

Before webhook registration, a server-side dry run obtains the Pod spec after Kubernetes defaults and admission mutation. The fixture signs its name, namespace, labels, and that complete spec with the approved key. With the webhook enabled, CREATE dry runs reject an unsigned request, accept the exact signed projection, and reject a harmless command change with the previous signature. The receipt checks each webhook decision and digest, verifies the returned projection, and confirms the Pod is absent from the API afterward.

## Verify the adopting signature boundary

## Portable evidence boundary

The retained 10-check case demonstrates an owned Ed25519 validating webhook on Kubernetes v1.36.1 for selected `core/v1` ConfigMap CREATE/UPDATE fields and an inert `core/v1` Pod CREATE server-side dry run. It verifies authorized signatures, unsigned and unrelated-signer denials, changed signed-field denials, unchanged stored state after a denied ConfigMap update, and a Pod spec mutation denial. It does not prove production signer custody, key lifecycle, webhook enrollment across clusters, or a GitOps controller path.

The portable ConfigMap projection signs `apiVersion`, `kind`, `metadata.name`, `metadata.namespace`, `metadata.labels`, `data`, `binaryData`, and optional `immutable`. The Pod projection signs `apiVersion`, `kind`, `metadata.name`, `metadata.namespace`, `metadata.labels`, and the entire defaulted `spec`. Other metadata fields and resource kinds are not covered by this proof. The Pod comparison is render/admission dry-run only; it does not persist or execute a Pod.

## Adopter procedure

1. **Define the signed object contract.** Enumerate each resource kind, API version, namespace scope, operation (CREATE, UPDATE), exact signed fields, defaulting/mutation order, and excluded fields. State whether the signed bytes cover individual resources, controller templates, generated Pods, or all of them. Do not infer coverage of a generated Pod from a signed Deployment template unless the actual webhook and signer produce and verify the Pod projection too.
2. **Inventory admission paths.** For each production/staging cluster and selected kind, trace both direct API submission and each deployed GitOps/deployment controller path to the API admission webhook. Record webhook match rules, namespace/object selectors, failure policy, timeout, CA bundle, service endpoints, and the effective signer allowlist. Verify ownership and restrict changes to the webhook configuration, backing service, trust roots, and admission policy.
3. **Bind approval to the artifact.** Retain an approved immutable source revision and review decision, the exact manifest digest/projection, signer identity and key version, and the reconciler's observed source revision. Confirm the controller submits the same signed object projection and the admitted live object matches it. A valid signature alone does not establish repository review or deployment authorization.
4. **Run an inert positive and negative comparison for each scoped path.** In an approved nonproduction namespace, for every kind/operation and each direct or controller submission path, admit one exact authorized signed object. Then submit a harmless unsigned object and a modified signed field or unapproved signer; verify the request is denied and no object is created or changed. For UPDATE, compare the pre/post stored object and resourceVersion. For GitOps, verify both the controller's successful approved revision and a denied inert revision without applying its object. Preserve an inert target and never use a real workload or production object for these probes.
5. **Exercise verifier failure closed.** On an owned test target, make the verifier unavailable or present an untrusted verifier CA and submit one unsigned inert object. The API must reject the request according to the configured failure policy, with no object mutation. Restore and recheck the approved positive path. An unavailable verifier must never silently become an authorization fallback.
6. **Rotate and retire keys deliberately.** Name the active signer and public trust version in the policy. Test an overlap window in which the approved new key works and the old key works only as long as policy permits. Re-sign every still-deployed artifact before removing the old public key; then confirm a fresh new-key signature is admitted and an old-key-only signature is denied. Keep signing private keys in the approved signer/HSM custody boundary; do not copy them into clusters or evidence.
7. **Retain reviewable evidence.** Keep the policy and webhook configuration digest, namespace/kind/verb match scope, signer key IDs and rotation record, source revision/review, exact manifest/projection digest, sanitized admission decision, denied/allowed response, and before/after object identity/resourceVersion. Record webhook health and failure-policy result. Do not retain private keys, bearer tokens, or unnecessary manifest payloads. Define audit retention, access, export and incident follow-up under the adopter's evidence policy.

## Do not overclaim

The portable receipt is mechanism evidence only for ConfigMap CREATE/UPDATE projection and Pod CREATE dry-run. OCI, other Kubernetes kinds, Pod-template/controller reconciliation, actual GitOps admission, organization-wide key custody/rotation, verifier outages, and production cluster coverage require separate adopter evidence. The paired live runs recorded in the current issue notes report 10 passing checks on two separate disposable clusters; the workspace copy retains the published receipt for one current run.

## Admission endpoint loss and recovery

The webhook runs in a separate infrastructure namespace so its controller
can recreate the verifier during an outage. The case scales the owned
verification endpoint down and confirms zero
ready EndpointSlice addresses. It submits an otherwise approved signed
request. The API reports a failure calling the configured webhook and
independently confirms the object is absent. After recovery, the same
request is admitted and its governed fields are read back.

For an adopted deployment, verify all applicable webhook registrations and
request paths, signer-key lifecycle, effective failure policy, and tested
availability and recovery objectives.
