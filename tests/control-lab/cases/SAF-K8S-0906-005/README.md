# SAF-K8S-0906-005 — Measure label drift and verify independent review

Run `python3 tests/control-lab/lab.py test SAF-K8S-0906-005 --docker-context desktop-linux` from the framework checkout.

The four checks use synthetic annotation and dataset records and native named-access decisions. They verify distinct review and authorized adjudication, exact dataset-version and asset binding, unresolved and inconsistent record holds, and a separately read release. The fixture compares a fixed earlier histogram to current first-review proposals. The observed shift prioritizes independent quality review and the original review authority and release results are preserved.

## Verify an adopted label workflow

1. Inventory human, automated, correction and administrative paths. Verify actual contributor, reviewer and adjudicator identity authorities, access scopes and separation. Join each exact user identity and decision to the dataset version and asset.
2. Review two independent approvals or authorized adjudication with controlled test data, including duplicate reviewer, stale or mismatched dataset or asset and unresolved records. Verify allowed and held outcomes directly at the trainer's release boundary.
3. Version historical histograms and agreement definitions, sample representative labels and document the decision to investigate a measured change. Independently assess causes, policy exceptions and any later approval of altered labels.
4. Preserve the protected change and review history, decision and artifact references, and ownership and retention evidence across correction and release paths.

- [Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)

The reviewed histogram difference is a label-shift observation for quality review. Investigate its sampling, authorized changes and context before assigning a cause. The test compares the release decisions independently of that observation.
