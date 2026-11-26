# SAF-K8S-0905-025 — Independent approval of model promotion

Run from the framework checkout.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0905-025 --docker-context desktop-linux
```

From the lab checkout, invoke `python3 lab.py` with the same arguments.
An authenticated fixture developer persists the fixed release approval
before policy activation. After resetting the release and enabling
native admission, the same developer request is refused and produces
no change. An independently authenticated reviewer persists approval
of the same release. The fixture's short-lived ServiceAccount
credentials remain in its temporary workspace.

## Verify the adopted promotion workflow

1. Inventory the actual promotion paths, model and release identifiers,
   developer and reviewer role ownership, identity provider, approved
   tenant scopes, and any quorum rule.
2. In an owned staging workflow, compare the same release submitted for
   developer self-approval and independent approval. Verify actual
   authenticated identities, effective role assignment, precise refusal
   and approved execution. Verify each direct or controller-mediated
   release path.
3. Where a quorum is required, independently test the actual quorum
   rule. Compare too few distinct eligible votes, duplicate votes and
   the accepted number. Preserve the role inventory, decision record,
   exact release identity and tenant boundary evidence.
4. Repeat after a role, workflow, identity provider or policy change.
   Retain decision and deployment review evidence with separate
   authority to change the policy, assign roles and approve promotion.

[Kubernetes ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
and [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final).
