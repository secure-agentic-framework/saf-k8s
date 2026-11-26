# SAF-K8S-0909-010

Run `python3 tests/control-lab/lab.py test SAF-K8S-0909-010` from the repository root. The case needs the pinned local Qdrant image, a Kind persistent volume provisioner and the adjacent disk tool fixture.

A plaintext comparator responds before TLS is enabled on the governed endpoint. The governed client verifies the server certificate and identity and recovers the owned point after Pod recreation. The native snapshot is exported in memory, written as LUKS ciphertext to a separate persistent claim, and recovered using the separate ephemeral key. The unrelated key fails. The recovered snapshot restores a separate Qdrant collection and reproduces its marker and vector.

The separate [active-volume guest test](active-volume-guest/README.md) binds the live Qdrant data path to a LUKS2-backed volume and verifies its point after mapper close, wrong-key denial, and readback in a fresh Kind cluster. Its [paired receipt](active-volume-guest/active-luks.verified.json) records both guest arms.

Verify active volume, snapshot and backup coverage, provider key authority and lifecycle in the actual deployment.

[Qdrant security](https://qdrant.tech/documentation/security/) · [Qdrant native snapshots](https://qdrant.tech/documentation/snapshots/) · [QEMU disk images](https://www.qemu.org/docs/master/system/images.html)
