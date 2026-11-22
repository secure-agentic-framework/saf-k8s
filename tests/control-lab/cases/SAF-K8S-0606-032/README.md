# SAF-K8S-0606-032 — GitOps drift detection and reconciliation

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0606-032 --docker-context desktop-linux
```

The runner verifies the Argo CD v3.6.1 release manifest checksum and pins
the Argo CD image digest. Inside the disposable cluster, a read-only HTTP
service serves a Git repository from a ConfigMap. The source commit is
built locally from the fixture and contains a marker and a Pod that reads it.

The case waits for Argo CD to sync the exact Git commit. It changes the
ConfigMap marker and observes `OutOfSync` while self-heal is disabled. It then
enables self-heal and checks that Argo CD returns to `Synced`, that the
ConfigMap matches Git, and that the same Pod sees the restored marker.

This fixture covers Argo CD reconciliation. Notification delivery and
actual GitOps enrollment and operations require separate evidence.
[Argo CD auto-sync and self-heal](https://github.com/argoproj/argo-cd/blob/v3.6.1/docs/user-guide/auto_sync.md).
