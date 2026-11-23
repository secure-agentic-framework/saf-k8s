# SAF-K8S-0205-011 Firewall change reconciliation

The case compares real snapshots of a detached table on its disposable Kind node. It detects a changed rule, rejects an attempt to overwrite the immutable baseline, verifies that the kernel syntax check leaves state unchanged, approves a detached preview before applying it to the live fixture table, and rechecks rollback.

The fixture chain has no packet hook. Production approval identity, periodic collection, provider audit trails and actual network policy enforcement require separate evidence.

```sh
python3 lab.py test SAF-K8S-0205-011 --docker-context desktop-linux
```
