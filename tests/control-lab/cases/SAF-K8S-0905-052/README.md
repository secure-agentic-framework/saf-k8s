# SAF-K8S-0905-052 — Publish approved model source records

Run the case by ID from the framework checkout.

    python3 tests/control-lab/lab.py test SAF-K8S-0905-052 --docker-context desktop-linux

Immutable proposals document the source kind and identifier, approval status, named reviewer and assigned evidence. The same publisher accepts an incomplete record while validation is disabled and rejects it when the criteria are enforced. A read-only reviewer evaluates the approved fixtures. The restricted publisher persists repository, publisher, and registry namespace approvals. Kubernetes denies a separate unprivileged writer. No listed source is contacted.

The criteria and reviewer records are fixture data. Verify the actual source inventory, identity and license evidence, ownership, approval strategy, and any deployed consumers before relying on the control in production.

- [Kubernetes 1.36 ConfigMaps](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/configmap/)
- [Kubernetes 1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
