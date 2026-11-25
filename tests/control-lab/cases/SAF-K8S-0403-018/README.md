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

From the SAF-K8S repository root, run `python3 tests/control-lab/lab.py test SAF-K8S-0403-018 --docker-context desktop-linux`.

## Adopter verification

Inventory the actual key authorities, workload identities, key domains, administrator roles and alternate credential routes. For each key, test the approved operation with a deployed test identity and repeat the same request with an unapproved role. Verify permitted use and denied cross-domain use, signing or administration, as applicable. Correlate issued identity, exact key/operation and observed outcomes in the actual provider audit. Check independent key administration, role revocation, and provider/HSM custody at the real authority.
