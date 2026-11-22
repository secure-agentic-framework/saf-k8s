# SAF-K8S-0606-025 CI artifact freshness

Run from the SAF-K8S framework checkout.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0606-025 --docker-context desktop-linux
```

A fixture Job authenticates the exact artifact and build metadata with a
run-local HMAC key. The promotion Job reads real commit objects from the
isolated Git bundle, verifies the receipt and artifact digest, and compares
both timestamps to a fixed reference epoch. The policy allows an age of
300 seconds, including the boundary. Each allowed artifact creates its own
inert ConfigMap. Stale source, stale build, future timestamps, and substituted
artifact bytes produce distinct rejections.

The timestamps are fixture inputs. Production timestamp integrity, signer
authorization, repository lineage and deployment coverage need separate
evidence. The compact receipt format is specific to this test.

- [SLSA v1.2 Build Provenance](https://slsa.dev/spec/v1.2/build-provenance)
