# SAF-K8S-0404-001 cert-manager issuer and issuance

Run the control by ID against fresh Kind. The runner verifies the
official cert-manager release manifest and pins the controller images.
A missing Issuer fails to provision the requested leaf. An in-cluster
CA issues a leaf with the expected trust, DNS name, key algorithm,
validity and renewal schedule. A Certificate specification change
triggers reissuance and replaces the key. The original leaf remains
cryptographically valid at its original DNS identity.

The case uses a disposable CA. Verify the actual organization provider,
custody, availability, scheduled renewals, deployment reload, and
issuer-driven revocation independently.

- [cert-manager CA issuer](https://cert-manager.io/docs/configuration/ca/)
- [cert-manager Certificate resource](https://cert-manager.io/docs/usage/certificate/)
- [cert-manager v1.21.3](https://github.com/cert-manager/cert-manager/releases/tag/v1.21.3)
