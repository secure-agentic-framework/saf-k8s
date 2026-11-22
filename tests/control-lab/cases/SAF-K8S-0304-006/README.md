# SAF-K8S-0304-006 — Host volume mount restriction

## Provenance

| Field | Evidence |
| --- | --- |
| Catalog commit and control permalink | `secure-agentic-framework/saf-k8s` commit `133a8698a45e2b335b51728bf4c62f7bda98d15f`; [control markdown at the pinned commit](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0304-006.md) |
| Pinned catalog entry | `saf_k8s_controls.yaml` at the same commit; the lab index records control SHA-256 `2cbb412e609dd2daaf3b701575e37397b0348dcffdb6678dd6673641ebbbc87e` |
| Primary Bead and any child beads | Not inspected or changed; Beads are outside this case-authoring scope |
| Reviewer and date | GPT-6; 2026-11-21 |
| Tested platform | Disposable kind with the pinned Kubernetes v1.36.1 node image. |
| Primary references for the tested versions | Kubernetes v1.36 Pod Security Standards, Pod Security Admission, namespace labels, and hostPath volume docs listed below |

## 1. Verify the claim

The pinned control says hostPath Pods must be denied by default through admission, with documented infrastructure exemptions and compensating controls recorded in an exemption register. Its enforcement text names Gatekeeper or Kyverno, while Kubernetes also ships Pod Security Admission (PSA). Kubernetes v1.36's Baseline Pod Security Standard forbids `spec.volumes[*].hostPath`; namespace `pod-security.kubernetes.io/enforce` labels select the level and `enforce-version` pins its policy version. That built-in mechanism is suitable for testing the hostPath denial obligation without installing a third-party engine.

| Obligation from the catalog | Mechanism and applicability | Evidence needed | Result |
| --- | --- | --- | --- |
| Deny hostPath Pods by default | PSA Baseline, namespace-enforced at `v1.36`; this check covers ordinary core/v1 Pod CREATE admission | Same hostPath Pod accepted before enforcement and denied after enforcement with a PodSecurity Baseline hostPath reason | Live assertion in the retained framework receipt |
| Preserve permitted ordinary Pod admission | A harmless `emptyDir` Pod is submitted to the same enforced namespace | Server dry-run returns the Pod object | Live assertion in the retained framework receipt |
| Limit documented infrastructure exceptions | This fixture does not create or approve exceptions | Production exception register, identity and namespace governance, compensating controls, review/expiry, and audit evidence | Separate governance review required; not established here |
| Cover all production Pods and namespaces | Namespace labels only express policy for namespaces carrying the labels; cluster defaults and exemption configuration affect coverage | Production inventory, API-server PSA configuration, namespace-label governance, policy audit logs, and workload review | Out of scope for this fixture |

Kubernetes Baseline rejects all hostPath volumes; it does not implement an approved-hostPath allowlist or the control's exception register. Do not treat a namespace-level label or an admission dry-run as proof that a real infrastructure exception is approved. PSA cluster exemptions are configured in API-server admission configuration; their scope and governance need separate review. The catalog can remain accurate as a requirement, but its implementation text should make clear that PSA Baseline is one enforcement option and that exception governance is a distinct control surface.

Versioned upstream references:

- [Kubernetes v1.36 Pod Security Standards](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-standards/) — Baseline requires `spec.volumes[*].hostPath` to be undefined.
- [Kubernetes v1.36 namespace labels and annotations](https://v1-36.docs.kubernetes.io/docs/reference/labels-annotations-taints/) — documents `pod-security.kubernetes.io/enforce` and `enforce-version`.
- [Kubernetes v1.36 admission controllers](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/admission-controllers/) — describes PodSecurity validating new Pods against the namespace's selected standard.
- [Kubernetes v1.36 volume types](https://v1-36.docs.kubernetes.io/docs/concepts/storage/volumes/) — describes hostPath risks and recommends avoiding hostPath where possible.
- [Kubernetes v1.36 cluster-level Pod Security Standards](https://v1-36.docs.kubernetes.io/docs/tutorials/security/cluster-level-pss/) — documents API-server defaults and namespace, username, and runtimeClass exemptions.

## 2. Make the test fail for the expected reason

`fixtures.json` defines one inert Pod request with a read-only mount declaration and the synthetic host path `/tmp/saf-hostpath-fixture`. The case submits it using `--dry-run=server` to a case-owned namespace before adding Pod Security labels. This red observation checks admission reachability and that another policy does not already reject the request. The case then pins Baseline enforce, audit, and warn to `v1.36` on that same namespace and submits the exact same request again.

The red phase must return the server-generated Pod object. The green phase must be an API `Forbidden` response with `violates PodSecurity`, `baseline:v1.36`, and `hostPath volumes` in the diagnostic. This exact denial category distinguishes policy enforcement from request timeouts and unrelated validation failures. No hostPath Pod is persisted or launched. The host path is only a string in the synthetic Pod spec: the case does not create, mount, stat, open, or read that path.

## 3. Implement the control and rerun

The case uses the Kubernetes built-in PSA Baseline policy, not Gatekeeper or Kyverno. It tests ordinary `v1/Pod` CREATE admission only. After the denial check, it submits a separate harmless Pod with an `emptyDir` volume using server-side dry-run and requires the API to return the Pod object. This positive control checks that the policy still admits a permitted non-hostPath Pod.

No exception is simulated. The exception language in the control refers to real infrastructure workloads and formal approval; fabricating an exception record in a disposable test would not establish exception governance. The test does not create any workload Pod, even for its positive control. It makes no changes to the framework or catalog.

Run from the control lab directory. The runner provisions a fresh cluster:

```sh
python3 lab.py test SAF-K8S-0304-006 --docker-context desktop-linux
```

The harness pins a Kubernetes v1.36.1 kind node image and records server version, command evidence, checks, and cluster cleanup in the run evidence. The rerun must retain `result.json` and relevant command output. This author performed static review only and did not invoke `lab.py`, `kubectl`, Docker, kind, or other cluster tooling.

## 4. Inspect and retain the evidence

Retained passing results are available at `verified/SAF-K8S-0304-006.json`. A rerun retains the API decisions, an empty Pod inventory and the cleanup result.

## 5. Record the disposition

| Field | Evidence |
| --- | --- |
| Outcome | Live policy behavior confirmed on the pinned kind fixture |
| What the test is designed to establish | A same-request hostPath admission comparison under unlabelled and v1.36 Baseline namespaces, plus admission of a harmless non-hostPath `emptyDir` Pod |
| What requires separate evidence | Production namespace coverage, API-server PSA configuration, any Gatekeeper/Kyverno deployment, approved exception governance and compensating controls, audit log delivery, and real infrastructure workload behavior |
| Proposed catalog correction | No catalog edit proposed. Clarify that built-in PSA Baseline can enforce hostPath denial, while its cluster-configured exemptions and organizational exception register require separate governance evidence. |
| Run paths and narrower follow-up beads | `saf-lab-0304-006` links both runs and the production evidence issue. |
