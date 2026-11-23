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
