# SAF-K8S-1006-007 — SSDF mapping and evidence-gap gate

Run from the SAF-K8S repository with a disposable Docker-backed Kind cluster:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1006-007 --docker-context desktop-linux
```

This case uses the lab runner's digest-pinned `kindest/node:v1.36.1` image and requires the API server to report Kubernetes `v1.36.1`. It creates a namespaced synthetic assessment CRD, then compares server-side dry-runs with a native Kubernetes `ValidatingAdmissionPolicy` inactive and active. It does not create or start the mock Deployment; its image reference is digest-pinned and its command is a reserved, inert placeholder. No external feeds or targets are contacted by the case itself.

## NIST source check

The official NIST publication inventory currently lists [SP 800-218 / SSDF v1.1 as Final (February 2022)](https://csrc.nist.gov/pubs/sp/800/218/final), [SP 800-218 Rev. 1 / SSDF v1.2 as Draft (initial public draft dated December 17, 2025)](https://csrc.nist.gov/Projects/ssdf/publications), and [SP 800-218A as a separate Final SSDF Community Profile for generative AI and dual-use foundation models](https://csrc.nist.gov/projects/ssdf). Thus v1.1 is the final core publication shown by NIST; v1.2 remains labeled a draft on the publication inventory checked for this draft.

`fixtures/ssdf-v1.1-tasks.json` transcribes the v1.1 Table 1 core task identifiers. It contains four groups, 19 practices, and 42 tasks: PO has 5 practices / 13 tasks; PS has 3 / 4; PW has 8 / 16; RV has 3 / 9. The numbering gap at PW.3 is intentional: NIST records former PW.3.1 as moved to PO.1.3; PW.4.3 moved to PW.1.3; and PW.4.5 was deleted in v1.1 and merged into PW.4.4. RV.3.4 is in core SP 800-218 v1.1 Table 1; SP 800-218A makes no addition to that task. The case checks every task ID exactly once and preserves its group and practice identifiers. Practice and task IDs are inventory keys, not a control-by-control claim that NIST mandates a Kubernetes implementation.

NIST describes SSDF as outcome-based, risk-informed guidance, says organizations can consider applicability, and says the practices are a starting point rather than a checklist. The catalog requires this mapping as a framework policy. NIST supplies risk-based recommendations with applicability informed by each organization. The case therefore does not assert that a producer, AI/ML team, Kubernetes deployment, or organization conforms to SSDF or federal requirements.

## Runtime checks

- **Red:** before the admission policy is installed, the API accepts a synthetic assessment with an omitted task.
- **Green:** after binding the policy to the test namespace, the same record is rejected for an incomplete SSDF task inventory. Separate probes require an accountable owner and review record and reject an altered fixture digest.
- **Positive:** a complete 42-task assessment is admitted while its illustrative gap, not-applicable, and unassessed statements remain marked pending and assigned to reserved fixture owners. The fixture policy also prevents synthetic inputs from declaring any task supported. This is a review-required evidence record, not a passing conformity attestation.

The assessment binds each statement to `synthetic-control-evidence.json` by SHA-256 and binds the task inventory and all local fixture references to their byte digests. `case.py` recomputes these hashes on the host, writes the inventory and hash observations to the runner's evidence directory, and constructs an admission policy that accepts only those exact local fixture paths and hashes. The runner transcript and result JSON preserve the raw API observations. The payloads contain only the synthetic fixtures and reserved placeholders; there are no credentials or secrets in this case.

## Coverage limits and unresolved claims

This is an admission-record contract test. It demonstrates that a native API gate can check a scoped synthetic SSDF mapping, its complete task inventory, immutable local references, and reviewer ownership for unresolved statements. It does not validate the truth, sufficiency, provenance beyond local fixture hashing, or organizational applicability of evidence. A hash binds bytes; it does not authenticate the author or establish that a claim is true.

The test does not inspect source repositories, CI/CD systems, software artifacts, model training or inference practices, team populations, third-party attestations, vulnerability response, recurring review, external GRC records, or deployed Kubernetes/AI environments. A deployment-level review would need a defined system and development scope, competent owners, supported applicability decisions, authentic source evidence, and independent assessment. No organizational data are present in these fixtures. The test also verifies that the API leaves a persisted assessment unchanged after rejecting an unsupported status update.

## Primary references

- [NIST SP 800-218 final publication page](https://csrc.nist.gov/pubs/sp/800/218/final) and [official Table 1 in PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf)
- [NIST SSDF publications inventory](https://csrc.nist.gov/Projects/ssdf/publications)
- [NIST SP 800-218A, final AI SSDF Community Profile](https://csrc.nist.gov/pubs/sp/800/218/a/final)
- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
