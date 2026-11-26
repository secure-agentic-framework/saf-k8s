# SAF-K8S-0701-006 — Dual authorization for a retained volume

Run from the lab checkout.

```sh
python3 lab.py test SAF-K8S-0701-006 --docker-context desktop-linux
```

From the framework checkout, invoke `python3 tests/control-lab/lab.py`.
The disposable Kubernetes case verifies an unbound PV deletion and a
separate bound local-path Retain volume containing one inert marker.
The approved executor submits the exact controlled operation. Native
admission requires votes from two distinct authorized fixture
ServiceAccounts on a ledger bound to the exact PV UID.

Before activation, the bounded Job submission reaches the API in dry
run. With the gate active, zero or one approved vote leaves the same
request denied and the independent marker unchanged. Two approvals
permit the Job to remove the one fixed marker. The executor cleans up
the exact authorized objects, and the independent node read verifies
the marker remains absent. The retained test directory is removed with
the disposable node.

## Verify the adopted retained archive control

1. Inventory every retained artifact and its exact PV, PVC, storage
   provider object and copy or snapshot identifiers. Record the
   approved retention and destruction path and which actual storage
   or API layer can enforce the decision.
2. Bind approvals from independently authorized people or roles to
   the actual immutable object identifier, action, authority and
   expiration. Verify separate approval ownership, reset and
   tamper controls, and logs for the exact request under test.
3. In an approved disposable representative environment, compare no
   approval, one approval, repeated or wrong approval, and two
   distinct valid approvals. Confirm the scoped operation refuses and
   state remains intact before authorization. Independently check the
   approved operation and its observed target state after authorization.
4. Verify provider destruction, retained copies and any sanitization
   obligation at the actual storage authority. Include alternate
   administrative, backup, snapshot and recovery paths. Retain
   receipts for the exact authorized inventory, decisions, timestamps
   and affected provider objects.

[Kubernetes ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
and [Kubernetes persistent volume lifecycle](https://v1-36.docs.kubernetes.io/docs/concepts/storage/persistent-volumes/).
