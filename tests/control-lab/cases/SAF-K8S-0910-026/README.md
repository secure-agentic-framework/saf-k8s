# SAF-K8S-0910-026 scoped writer candidate

This scratch-only candidate adds one grouped assertion to the existing six-check case. It does not modify the published case, receipts, catalog, Beads, or runner.

## Candidate behavior

The existing case is retained, including its two separately owned Kubernetes v1.36.1 API servers, original approval protection, native admission deny/allow comparisons, and decision parity. The added phase replaces the runner-side `kubectl apply` with one short-lived in-cluster writer Pod in each member fixture:

- The runner parses the pinned policy YAML and builds a deterministic JSON envelope. The immutable approval record binds both the original YAML digest and envelope digest. The fixture copies only that observed approval and same envelope into the owned peer.
- Each cluster has a non-enforcing placeholder at the exact policy/binding names. The writer ServiceAccount can `get` only the three named fixture ConfigMaps and `patch` only the exact named ValidatingAdmissionPolicy and Binding. It cannot create cluster resources or write approval state.
- The Pod explicitly projects a short-lived API token, mounts the public in-cluster API CA, and sends fixed requests only to `kubernetes.default.svc`. The Python writer checks approval version, both digests, resource kinds, and exact names before patching. It reports booleans only; no token, response body, or policy bytes are written to output.
- A wrong-version envelope retains the approved bytes and digest but changes the version. The writer must report `withheld` without a write; host-side API reads confirm both placeholders remain unchanged. The approved envelope is then applied and both resources read back before the original type-check and admission checks continue.
- Every writer Pod is bounded by an active deadline, small CPU/memory requests and limits, and explicit cleanup. All fixture resources remain inside the two isolated Kind clusters; the peer helper deletes its owned peer in `finally`, and the outer lab runner deletes its local cluster.

## Expected evidence

The original six assertions remain. One grouped `green` assertion is added, for seven total:

1. Two distinct owned targets.
2. Successful writer Pods used the exact writer ServiceAccount.
3. Version, source-bundle digest, envelope digest, and fixed resource names matched the immutable approval.
4. Both approved resources read back with the expected policy/binding specs.
5. Wrong-version envelopes were withheld in both clusters and placeholders remained unchanged.
6. Both APIs still accepted a compliant Deployment after the wrong-version attempt.
7. The original compliant Deployment remained accepted by both APIs after approved distribution.

The new check's `observed` record is normalized to booleans. The detailed outcome file keeps sanitized decisions and check predicates; it contains no projected token and does not include policy body or HTTP response body. The Pod code catches API failures without serializing exception contents.

## Static integration notes

This directory is a standalone reference case. The control-lab CLI does not load a case directly from this scratch path; for a reviewed run, stage the candidate as a disposable case snapshot and use the normal review/approval workflow. `case.py` locates the existing `SAF-K8S-0908-001` Python 3.13.2 image loader and `SAF-K8S-0910-020` owned peer helper from either the workspace or a case directory. The host interpreter needs PyYAML for deterministic conversion of the two YAML documents; the in-Pod writer uses Python standard library only.

This mechanism proves a restricted in-cluster member-side writer on two synthetic clusters. The test runner still creates the central approval object and mirrors its observed bytes to the peer. It does not prove the adopter's production approver, cross-cluster transport, member discovery, rollout/recovery, full system baseline, or configuration scope beyond this one admission policy.

No Docker, Kubernetes, Git, or Beads commands were run while preparing this candidate.
