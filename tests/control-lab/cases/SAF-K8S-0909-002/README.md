# SAF-K8S-0909-002

Run `python3 tests/control-lab/lab.py test SAF-K8S-0909-002` from the SAF-K8S repository root. The case uses the pinned Cosign and Python images on a local Kind cluster. The signing key exists only during local fixture setup.

The ungoverned baseline accepts an alternate model and emits a different vector. The governed workload first verifies an offline signature over the exact model with a pinned local public key. A mismatched signature stops initialization. An alternate model with a matching signature still fails the separate approved digest check. Two separate Pods embed the approved UTF-8 fixture and return the expected vector. A pinned, malformed benign document ends before embedding.

Independently verify production signer authorization, custody and revocation, policy selection, transparency requirements, parser coverage, and approved reproducibility tolerances across the supported runtime and hardware.

[Sigstore signature verification](https://docs.sigstore.dev/cosign/verifying/verify/) · [NIST Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

## Verify an adopting implementation

Verify production signer authorization, exact subject digest binding,
trusted key distribution, revocation/transparency policy and supported
parser/runtime path. Demonstrate signature and digest failures stop model
initialization before inference, and compare an approved synthetic vector.
The fixture uses Cosign verification and a fixed UTF-8 toy model. It does
not prove real model quality or reproducibility across hardware.
