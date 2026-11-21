# SAF-K8S-0101-008 — Metadata-only API audit default

## Coverage

The runner-owned default kind v1.36.1 cluster is the unaudited baseline. The
case creates an empty synthetic ConfigMap marker in `saf-test`, then confirms
the static kube-apiserver manifest has no `--audit-` flags and that
`/var/log/kubernetes/audit.log` is absent. The same create is sent to a second,
disposable kind cluster using the minimal catch-all `Metadata` policy. The
audited cluster's local event filter returns only the verb, level, namespace,
stage, and whether request/response body fields exist. It never returns raw
audit lines or any event body. No Secrets, TokenReviews, authentication
tokens, decision requests, or body-level audit events are created.

The `Metadata` default applies to all API requests in the second disposable
cluster. Only the marker's `ResponseComplete` event is summarized. Its audit
file is ephemeral inside the kind node; no rich log collection from Kubernetes
background traffic is performed. The audited kind configuration is rendered
in a temporary file named `audited-kind-config.yaml` with an absolute policy
path resolved from this case file. The runner's default cluster therefore
remains the baseline.

## Supported versions

- Tested runtime: kind node image pinned by `lab.py`, Kubernetes v1.36.1.
- Documentation checked: Kubernetes v1.36 auditing documentation.
- No other Kubernetes minor or managed control plane is claimed as tested.

## Primary references

- [Kubernetes v1.36: Auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/): audit levels, first-match behavior, `--audit-policy-file`, and the minimal all-requests `Metadata` policy.
- Pinned catalog control: `SAF-K8S-0101-008` at framework commit `133a8698a45e2b335b51728bf4c62f7bda98d15f`, `markdown/controls/SAF-K8S-0101-008.md`.

## Verification gaps and scope corrections

This case covers the Metadata baseline. Credential-bearing Request-level
auditing and how to report authentication and authorization decisions are
tracked in `saf-lab-0101-008.1`. The case sends no TokenReview or decision
request and retains only fixed fields from the synthetic ConfigMap event.

The case does not verify whether real production or managed clusters have the
policy flag enabled, whether policy exceptions or rule ordering create
coverage gaps, or whether audit backends persist, retain, protect, deliver, and
alert on events.

## Live verification

The first passing lab run confirmed the create in both profiles and the audit
event only in the enabled profile. Both disposable clusters were deleted.
