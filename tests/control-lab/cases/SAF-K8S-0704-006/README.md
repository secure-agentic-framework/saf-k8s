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

## Adopter verification

1. Approve workload-specific RTO/RPO and identify provider-managed control-plane, storage, identity, network, and regional dependencies under the contract.
2. Exercise recovery into the approved alternate region or target. Verify checkpoint freshness and integrity, backup retention, PVC/storage compatibility, identities and network restoration, and application reads after recovery.
3. Measure actual recovery time and data-loss interval against the approved objectives. Include failed dependency branches and the operator roles needed to recover.
4. Retain the exercise approval, source/target, checkpoint digest, data-loss measurement, elapsed time, service validation, and exceptions. Kind's PVC result is portable checkpoint evidence, not managed-service or region recovery proof.
