# Verify a portable checkpoint restore on Kind

```sh
python3 lab.py test SAF-K8S-0704-006 --docker-context desktop-linux
```

A primary service writes a public checkpoint to a PVC and exports its exact
bytes. The fixture observes a later write and then takes the owned deployment
offline. Recovery verifies the saved digest, initializes a different PVC and
reads the restored state through the standby service. The evidence records
measured recovery time and the one-sequence difference from the last write.

The exercise uses Kind storage and namespaces. Verify managed control-plane
recovery, provider region and dependency recovery, portability and deployed
RTO/RPO separately.
