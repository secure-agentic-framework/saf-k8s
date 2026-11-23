# Verify provenance against independently assessed builder trust

```sh
python3 lab.py test SAF-K8S-0604-011 --docker-context desktop-linux
```

This fixture uses BuildKit provenance and actual Cosign signatures for the
same immutable build. The release evaluates the signer and builder against
a separately authenticated governance record. It rejects a signed high-level
claim from the lower-assessed signer, an unknown signer, a different digest,
and stale or unauthorized governance. The approved digest then runs in Kind.

The builder assurance levels are fixture policy inputs. A production SLSA
level requires assessment of the actual build platform and release process.
