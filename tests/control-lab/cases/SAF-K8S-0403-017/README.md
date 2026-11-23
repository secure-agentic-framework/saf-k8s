# SAF-K8S-0403-017 Workload key hierarchy

Run `python3 lab.py test SAF-K8S-0403-017` with the recorded revision. It uses
ephemeral Vault Transit, TLS, Go AES-GCM and synthetic application objects.
The comparison exposes the consequence of one shared wrapping key. Scoped
training/model keys and a separate Ed25519 signer then enforce specific
domains. The case verifies a training-only rotation, rewrap, and retirement
of the previous key version. Go is required to build the local envelope probe.

The application records persist only encrypted bytes and wrapped data keys.
The lab authority has in-memory custody. Production HSMs, external storage
integrations, governance and deployment-specific recovery require separate evidence.

- [Vault Transit API](https://developer.hashicorp.com/vault/api-docs/secret/transit)
