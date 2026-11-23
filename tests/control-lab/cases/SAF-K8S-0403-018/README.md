# SAF-K8S-0403-018 Key access by workload and operation

Run `python3 lab.py test SAF-K8S-0403-018` using the recorded catalog revision.
An isolated TLS Vault validates actual projected Kind service-account tokens
using Kubernetes TokenReview. Workloads exercise approved crypto operations
and receive distinct Vault policies for training, serving, signing, and
governance. The observed ACL decisions include login, encryption, decryption,
signing, policy administration and rotation.

The case correlates provider audit paths to the scoped policies and checks
a real permission removal. The disposable provider and synthetic identities
require separate production-provider and HSM evidence.

- [Vault Kubernetes authentication](https://developer.hashicorp.com/vault/api-docs/auth/kubernetes)
- [Vault Transit API](https://developer.hashicorp.com/vault/api-docs/secret/transit)
