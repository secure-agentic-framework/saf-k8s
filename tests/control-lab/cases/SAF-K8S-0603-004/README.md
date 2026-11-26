# Verify a staged artifact-signing migration

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0603-004 --docker-context desktop-linux
```

The pinned reference verifies classical and post-quantum signatures over an exact digest-bound manifest. It compares the classical stage, the dual-signature requirement and the post-quantum-only cutover for five inert lifecycle artifact classes. It refuses missing or misbound signature, signer, digest or inventory evidence. The disposable workload verifies the same accepted bytes.

For adoption, inventory training inputs, weights, checkpoints, embeddings, inference outputs and other included artifacts. Record required retention and supported algorithm, library and signer choices. Plan and approve coexistence, staged rollout, cutover, fallback and retrieval of prior trusted evidence. Verify authorized signer identity, exact manifest and byte coverage, downgrade refusal, interoperability and retained verification. Review key management and custody and document applicable exceptions. Evaluate encryption and key establishment under their own requirements.

[NIST FIPS 204 ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) · [NIST FIPS 205 SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final) · [NIST FIPS 203 ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
