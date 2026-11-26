# SAF-K8S-0905-052 — Publish approved model source records

Run the case by ID from the framework checkout.

    python3 tests/control-lab/lab.py test SAF-K8S-0905-052 --docker-context desktop-linux

Immutable proposals document the source kind and identifier, approval status, named reviewer and assigned evidence. The same publisher accepts an incomplete record while validation is disabled and rejects it when the criteria are enforced. A read-only reviewer evaluates the approved fixtures. The restricted publisher persists repository, publisher, and registry namespace approvals. Kubernetes denies a separate unprivileged writer. No listed source is contacted.

An independently authenticated reviewer Job writes the approval digest to its named Kubernetes record. The publisher has read access to that record and cannot approve its own proposal. A complete proposal fails publication before independent approval, then the publisher reads the matching digest and publishes it. All source identifiers and related evidence are synthetic.

## Verify an adopting implementation

Document the approval criteria, version, accountable reviewer and allowed source types. Use stable repository and publisher identities verified with authoritative records. Require the relevant provenance, permitted use, licensing, and ownership evidence. Bind every approval to the exact proposal version or digest, verify that independent authorized reviewers can publish approvals, and confirm operators or automated publishers cannot approve their own changes.

At governed intake boundaries, inventory which consumers load the approved list and independently observe an approved source and an unlisted one through their actual policy. Record the policy inputs, sanitized outcomes and evidence references. Separately verify scheduled revalidation and source retirement where required.

- [Kubernetes 1.36 ConfigMaps](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/configmap/)
- [Kubernetes 1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
