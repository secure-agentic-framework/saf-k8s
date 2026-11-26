# SAF-K8S-0403-002 — Verify external provider access, synchronization and recovery

Run from the lab checkout.

```sh
python3 lab.py test SAF-K8S-0403-002 --docker-context desktop-linux
```

From the framework checkout, invoke `python3 tests/control-lab/lab.py`.
The pinned External Secrets Operator reaches an owned HTTPS source.
Two independent test principals exercise the Webhook provider's
configured header and labeled Secret handling. The provider accepts
the approved request and refuses the other. The Kubernetes API admits
the alternate target declaration in a dry run, and its real
ExternalSecret cannot persist a target after the provider refuses it.

The separate native policy refuses an ordinary write to the protected
synchronized target and allows the selected controller to reconcile.
A continuing workload reads the approved synchronized marker. A
controlled provider outage marks reconciliation failed and retains the
previous version under the configured policy. After recovery the same
workload reads the newly synchronized value.

## Verify the adopted delivery path

1. Identify the actual issuer, provider and account, TLS trust, controller
   or direct mount driver, resource paths, and consumer. Exercise an
   authorized owned reference and an independently refused actor or
   resource under the same provider. Verify no disallowed copy persists.
2. Inventory synchronization intervals, propagation delay, application
   reload and the accepted stale window. Test source outages and
   recovery. Independently observe operator status, stored or mounted
   versions and the exact version consumed by the continuing workload.
3. For synchronized copies, independently verify actual access controls
   and encryption at rest. For direct delivery, inspect the effective
   mount and lifecycle. Verify any permitted bootstrap credential and
   plaintext exception separately.
   [SAF-K8S-0101-003 demonstrates a live API Secret storage rewrite](https://github.com/secure-agentic-framework/saf-k8s/blob/1baf617a23b9d6351fa7454cee10105cf83f0ce8/tests/control-lab/cases/SAF-K8S-0101-003/README.md).
4. Confirm actual provider rotation, expiry or revocation at the
   accepting service where required. Retain effective configuration,
   allowed and refused results, measured stale and recovery windows,
   permission evidence and ownership without raw credentials.

[External Secrets Operator Webhook provider](https://external-secrets.io/latest/provider/webhook/)
and [ExternalSecret refresh settings](https://external-secrets.io/latest/api/externalsecret/).
