# SAF-K8S-0403-020 KMS key least-privilege policy

Run `python3 lab.py test SAF-K8S-0403-020` from the lab directory using its verified
catalog revision. The native API server calls a KMS v2 bridge that uses TLS
Vault Transit. A separate policy-controlled workload first has broader
permission, then cannot wrap or unwrap the Secrets-protecting key. The
APIServer credential remains limited to its own Transit key operations,
and Vault audit records its wrapping and cold-start unwrapping.

The kube-apiserver receipt checks an exact owned Secret record. Private
fixture values and audit entries stay out of published output. Go and
OpenSSL are required. Managed cloud key policies, grants and continuing review
need separate environment evidence.

- [Kubernetes KMS provider](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/kms-provider/)
- [Vault Transit API](https://developer.hashicorp.com/vault/api-docs/secret/transit)
