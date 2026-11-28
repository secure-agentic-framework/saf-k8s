# SAF-K8S-0804-006 Authenticated artifact context and recipient binding

The case runs two exercises against a fresh Kind cluster. It requires Docker,
Kind, kubectl, and Go 1.24 or later. From the control lab directory run
`python3 -Bu lab.py test SAF-K8S-0804-006`. Use the reviewed catalog index and
Docker context for your checkout as described in the control lab instructions.

First, a local Go fixture encrypts an inert public marker and stores ciphertext
and synthetic context in an immutable ConfigMap. Four checks cover the unbound
baseline, independent policy, measurement and ciphertext changes, the approved
API round trip, and independent changes to artifact identity, expected plaintext
digest and synthetic recipient. The fixture verifies exact record metadata before
counting opens or denials.

Next, a broker Pod creates an ephemeral AES-GCM key and makes an encrypted
marker available over TLS. The approved workload generates a separate RSA key
inside its own Pod. The broker asks the Kubernetes API to authenticate the
projected token and verifies the requested audience, service-account name and
UID, and exact Pod UID. The broker binds each signed proof to the artifact
identity, ciphertext digest, synthetic policy and measurement, recipient key,
service-account and Pod identities, a fresh challenge, and an expiry. A separate
fixture signer signs the proof with Ed25519.

Three additional checks cover the workload identity, signed proof bindings, and
artifact opening. The approved Pod must unwrap the key and verify the decrypted
marker. A concurrent duplicate and a subsequent retry must receive no wrapped
key. The evidence includes the result and normalized observations. Fixture
private keys, bearer tokens, and wrapped keys are kept out of the published
receipts. Kind deletes the fixture cluster after the run.

The broker demonstrates a one-use release in one process and uses a synthetic
measurement. An adopted platform is required to verify hardware sealing or
measured attestation, production trust roots and key custody, and behavior
during migration, revocation, failover, and recovery.


## Live Confidential Space reference

The approved image decrypted the encrypted fixture. STS rejected the replacement image until the relying-party policy and key grant approved it, after which the replacement decrypted the same ciphertext. An independent call through the same key rejected tampered ciphertext.

[Shared reproducer and evidence](../../references/gcp-confidential/README.md)
