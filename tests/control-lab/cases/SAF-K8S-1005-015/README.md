# SAF-K8S-1005-015

Restricted, tokenless Kubernetes Jobs check a plain-text fixture against a pinned SHA-256
measured before the synthetic exercise. The bypass comparator accepts changed bytes.
The enabled Job rejects the changed fixture even with approved metadata, and rejects
matching bytes with pending approval. Matching bytes and approved metadata validate.
A native API probe also verifies that stored ConfigMap data are immutable.

The approval is synthetic metadata and the digest validates byte identity. The exercise
contains no AI model. Authentic reference provenance, signatures, model behavior, registry
operations and post-incident monitoring require separate evidence.

- [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
- [Kubernetes immutable ConfigMaps](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/configmap/#immutable-configmaps)
