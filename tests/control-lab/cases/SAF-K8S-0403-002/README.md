# SAF-K8S-0403-002 External Secrets Operator

Run `python3 lab.py test SAF-K8S-0403-002` with the catalog revision recorded in
the verified result. The case installs the pinned External Secrets Operator
chart and image. A separate disposable HTTPS API supplies public markers.
A scoped Kubernetes policy rejects an ordinary write to the synchronized
target while allowing the controller to reconcile it.

The running workload reads the synchronized Secret. A provider error is
visible as failed reconciliation and the last copy remains. On recovery, a
new version is synced and the same reader sees it. The provider is a
disposable fixture. Actual cloud or Vault authorization, direct CSI delivery,
and rotation or revocation at the accepting system require separate evidence.

- [External Secrets Operator refresh](https://external-secrets.io/latest/api/externalsecret/)
- [External Secrets Operator Webhook provider](https://external-secrets.io/latest/provider/webhook/)
