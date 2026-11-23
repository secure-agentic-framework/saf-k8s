# SAF-K8S-0602-007 — Emergency review record integrity

Run `python3 lab.py test SAF-K8S-0602-007` from the control lab.

The fixture stores an inert request in a dedicated ConfigMap. RBAC limits
approval to two separate ServiceAccounts. Native admission associates each
approval field with its reviewer and freezes the request ID, target digest,
and recorded expiry. The requester can read the approvals and cannot
approve the request or gain Pod-create permissions.

The fixture exercises custody of a synthetic approval record. The recorded
deadline is immutable. Trusted-time enforcement, actual expiry, audit
delivery, revocation, and the deployed emergency process need separate
evidence. The ConfigMap has no consumer that admits images or launches Pods.
