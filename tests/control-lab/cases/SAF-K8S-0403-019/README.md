# SAF-K8S-0403-019 Kubernetes KMS v2 provider

Run `python3 lab.py test SAF-K8S-0403-019` from the lab directory with the
catalog revision in the verified result. The case requires Go and OpenSSL.
It starts a disposable TLS key authority in its own Docker container and
an official Kubernetes KMS v2 protocol bridge on an owned Kind control-plane
node. The key remains in the authority's process. No key bytes, token values,
or raw etcd Secret records are published.

The comparison observes one exact plaintext fixture record, a new KMS v2
envelope, and the existing record's migration after rewrite. The API restarts
before final reads so the authority independently observes an unwrap. Real
HSM or managed-service key custody, production failover and provider
authorization require separate evidence. The case removes its provider and network.

- [Kubernetes KMS integration](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/kms-provider/)

## Adopter verification

1. Record the supported Kubernetes release, effective API resource scope,
   approved KMS authority, write provider, and integration identity and trust.
   Document separate provider, control-plane and key-administrator ownership.
2. In an authorized representative environment, create a named synthetic
   Secret and record the approved provider operation. Verify the exact stored
   envelope and an authorized read. Use sanitized statuses and labels. Keep
   Secret data and credentials out of the evidence.
3. Capture the known prior storage state of a named approved fixture record.
   Apply the supported rewrite, verify its new envelope, and verify exact
   authorized read-back after a cold API instance or provider-equivalent
   recovery. Confirm observed scope against the resource inventory.
4. For managed services, obtain version-specific evidence of application-layer
   protection, key ownership and covered migrations. Keep key authorization
   and policy review tied to [SAF-K8S-0403-020](../SAF-K8S-0403-020/README.md).
