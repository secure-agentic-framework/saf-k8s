# Verify build attestations against signer policy

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0603-007 --docker-context desktop-linux
```

Inert artifacts and case-generated test keys exercise signatures, exact subjects and payloads for the build environment and process. An immutable policy supplied to the consumer before the envelope pins the approved signer for each category, the predicate type, the exact subject and the expected payload hash. Both approved categories verify. A valid signature over the same environment payload from the process signer is refused by the environment policy. The receipt records decisions and booleans.

For adoption, capture the platform and applicable build transformations during an actual build, bind both evidence categories to the released artifact digest, and verify separation from developer-controlled steps. Supply approved signer identities through an independently managed trust policy. Exercise a known approved build and compare a signer or digest mismatch at the actual promotion boundary. Record the policy version, approved producer, build and artifact identity, verification outcome and retention instructions. The portable case covers consumer policy with its own test keys. Trusted producer isolation, concurrent capture, key custody and the deployment decision remain follow-up scope.

[NIST SP 800-204D section 5.1.1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204D.pdf#page=25)
