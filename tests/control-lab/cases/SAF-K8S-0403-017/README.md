# SAF-K8S-0403-017 — Vault Transit key domains and workload identities

Run from the lab checkout.

```sh
python3 lab.py test SAF-K8S-0403-017 --docker-context desktop-linux
```

From the framework checkout, invoke `python3 tests/control-lab/lab.py`.
The disposable Vault service compares a shared wrapping key with separate
training and model wrapping keys. The case persists only synthetic
ciphertext and a wrapped key. Application decryption verifies the exact
marker and associated context. A separate asymmetric signing key verifies
the approved marker and refuses a changed marker.

Three owned Kubernetes workload identities use separately mounted,
short-lived projected tokens. Vault checks the expected audience and
bound ServiceAccount. Approved roles can use their own data or signing
domain and receive refusal when using an unrelated domain. Rotation of
the training wrapping key preserves old authorized reads until rewrap.
The tested retired version subsequently fails the old unwrap path.

## Verify the adopted key hierarchy

1. Inventory the governed data, workload and storage boundaries. Link
   each training dataset, checkpoint, model artifact, inference consumer,
   backup and signing path to its exact provider key, purpose, approved
   identity, authentication method and protected custody.
2. Verify provider-managed key metadata and independent role assignments.
   Use owned test artifacts to compare expected encryption or unwrap,
   incorrect identity or context, cross-domain refusal, and separate
   verification of approved and changed signed content.
3. Observe a real key version change on the adopted authority. Confirm
   new writes use the new version. Inventory old dependencies and
   verify rewrap or re-encryption and authorized read-back before
   retiring the old version. Preserve a separately approved recovery
   path and verify that obsolete access is rejected.
4. Independently establish any required HSM, key export, vault storage,
   Kubernetes API encryption, PV and backup properties. Verify the
   transition and retained copies at each actual provider. Retain scoped
   outcomes and versions without key material or credential values.

[Vault Kubernetes authentication](https://developer.hashicorp.com/vault/docs/auth/kubernetes)
and [Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit).
