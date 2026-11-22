# SAF-K8S-0201-005 — Kubelet hostname override governance

```sh
python3 lab.py test SAF-K8S-0201-005 --docker-context desktop-linux
```

The case uses a fresh kind Kubernetes v1.36.1 node. It compares its registered
Node name and operating-system hostname, reads just the effective override
argument, and checks the API server declaration for the Node authorizer and
NodeRestriction. It does not change node names or use credential material.

A synthetic negative provisioning fixture includes duplicate names and
unapproved overrides. The corrected fixture requires distinct names, ordinary
hostname consistency, and a justified exception for the approved override.
The separate authorization fixture checks the documented username and group
form for the authenticated kubelet identity.

The hostname flag sets a naming input. Node authorization evaluates the
kubelet's authenticated identity and requires the node name in that identity
to match the registered Node. Production naming, enrollment and provider
controls need their own evidence under `saf-lab-0201-005.2`.

- [Kubernetes v1.36 Node authorization and naming](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/node/)
- [Kubernetes v1.36 kubelet options](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kubelet/)
