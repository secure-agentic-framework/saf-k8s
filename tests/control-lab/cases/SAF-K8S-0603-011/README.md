# SAF-K8S-0603-011 — Signed attestation policy revisions

Run `python3 lab.py test SAF-K8S-0603-011` from the control lab.

The disposable case signs two API-normalized Kyverno policies using a policy
author key. Independent promotion and rollback authorities bind approval to
the exact source and destination policy digests. The same applier rejects
tampered content, independent-approver mismatches, and stale source state.
Kubernetes RBAC rejects direct updates by the fixture author, and the scoped
applier uses the current resource version.

The test reads back the full effective policy specification and observes
real differences in server-side admission. Promotion admits one fixture
attestation tier; authorized rollback restores the previous tier.
Production branch protection, applier custody, control of admin paths,
persistent audit delivery, and rollout coverage need separate evidence.
