# Verify scan evidence before image promotion

Run from the framework repository. Use an OpenSSL 3 executable on the host. If needed, set `SAF_OPENSSL` to its path.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0601-008 --docker-context desktop-linux
```

Pinned OSV-Scanner scans two inert image archives offline against a synthetic advisory. The Kind promoter verifies the exact report using a separately mounted immutable Ed25519 trust policy. It refuses a valid report signed by an unapproved fixture key. The same signature also fails when the envelope claims the approved signer. Missing, stale or misbound reports, blocking findings, and out-of-scope exceptions each leave no release tag. A separate registry reader confirms approved exact digests and blobs are present.

For adoption, inventory actual candidate paths, platform manifests and scan coverage. Verify the scanner identity, signature policy, advisory source and revision, exact scanned digest, completion and report age. Exercise approved and refused examples at the effective promotion path, verify the registry contents independently, and inventory alternate writers. Record the approving authority, exact exception scope, expiry and retained decision evidence. The reference uses synthetic advisory data, keys and an exception record.

[OpenSSL 3 Ed25519 verification](https://docs.openssl.org/3.3/man7/EVP_SIGNATURE-ED25519/)
