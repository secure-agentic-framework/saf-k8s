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

## Adopter verification

1. Identify the authoritative build/source timestamp producers, signer
   authorization, trusted clock, freshness threshold, and every promotion
   entry point.
2. Confirm the deployed verifier binds the receipt to exact artifact bytes
   and repository lineage; run approved fresh/boundary and stale/future or
   substituted-byte cases against inert promotion targets.
3. Retain signer and clock trust evidence, policy configuration, per-path
   deny receipts, and audit records showing that bypass routes are absent.

Open child: `saf-lab-0606-025.1`. Native receipt: 8 checks.
