# SAF-K8S-0904-013 artifact storage encryption and access policy

The case uses the pinned SeaweedFS 4.53 S3 backend and a fixed public marker in
a case-owned bucket. Two disposable Pods have fresh emptyDir volumes. The
only storage configuration change is enabling s3.encryptVolumeData. An
authenticated PUT and GET round trip must preserve the exact marker digest
in both modes.

A read-only sidecar uses the on-disk index to find the marker's volume
record. The unencrypted record contains the exact fixture bytes. With
encryption enabled, the indexed record is populated and differs from the
unencrypted data, and neither the record nor its data file contains the
plaintext marker. The stored representation is checked before testing access
policy. The raw receipt keeps separate on-disk digests and record evidence.

The authenticated administrator adds a read-only bucket policy for the single
fixture marker and reads the policy back. With that grant, the anonymous GET
returns the marker and a fixed anonymous PUT is denied. Removing the grant
denies the same GET and PUT with the targeted S3 responses. The approved
bucket-scoped identity still reads the marker and writes and reads back a new
one. The service is cluster-private and telemetry is disabled. All accounts
and data are inert fixture values.

This case verifies one backend's volume bytes and bucket policy behavior.
Deployed provider policy, key custody and rotation, identity federation,
workflow context, durable storage and backups, and production transfer
protection require separate evidence.

- [SeaweedFS 4.53 S3 upload implementation](https://github.com/seaweedfs/seaweedfs/blob/4.53/weed/s3api/s3api_object_handlers_put.go)
- [SeaweedFS 4.53 embedded server configuration](https://github.com/seaweedfs/seaweedfs/blob/4.53/weed/command/mini.go)
