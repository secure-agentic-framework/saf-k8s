# SAF-K8S-0701-001 — PV/PVC access modes and effective writes

```sh
python3 lab.py test SAF-K8S-0701-001 --docker-context desktop-linux
```

The case uses Kubernetes v1.36.1 and its kind local-path StorageClass. A scoped
PVC policy first denies an unapproved access mode that the same API previously
accepted as a server dry-run. The permitted ReadWriteOnce claim then binds. Two
nonroot Pods owned by the lab run on one node and deliberately share one
ReadWriteOnce PVC. The first Pod writes an inert marker; the second reads and
changes it through its authorized writable mount. The two Pods confirm the
same data through the bound volume.

On the second Pod, a separate container mounts the same PVC with
`volumeMounts[].readOnly: true`. Its mount reports `ro`, reads the new
marker, and returns a read-only filesystem error on a file creation request.
Access mode determines PV/PVC matching and can constrain placement. Pod
permission to use the claim and the effective filesystem and backend
permissions govern an actual write.

ReadWriteOncePod depends on a compatible CSI driver and sidecars. Its
single-Pod mount behavior, other storage backends, and workload-specific data
or tenant authorization require their own evidence.

- [Kubernetes v1.36 PersistentVolume access modes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/persistent-volumes/#access-modes)
- [Kubernetes v1.36 read-only mounts](https://v1-36.docs.kubernetes.io/docs/concepts/storage/volumes/#read-only-mounts)
- [Kubernetes CSI ReadWriteOncePod](https://kubernetes.io/docs/tasks/administer-cluster/change-pv-access-mode-readwriteoncepod/)

## Pod references to a protected claim

The case then gives two synthetic identities permission to submit Pods in
the owned namespace. Before enforcement, the otherwise unrelated identity
can submit a dry-run Pod referencing the protected claim. The scoped policy
refuses that exact tuple. The approved identity can still reference the claim,
and the unrelated identity can still submit an ordinary no-claim Pod. These
requests use server-side dry-run and create no workload or extra claim.

For adoption, inspect the actual caller identity and policy for workload
references, effective storage and mount permissions, and the exact CSI
driver and sidecar support for the required access modes. Test the distinct
authorization and storage behavior with approved representative inputs.
Record any relevant Article 4a contribution only for covered data and the
effective mechanisms that govern its re-use.
