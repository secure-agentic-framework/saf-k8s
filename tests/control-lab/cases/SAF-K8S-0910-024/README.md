# SAF-K8S-0910-024 model provenance and peer trust lifecycle during registry replication

Run `python3 lab.py test SAF-K8S-0910-024` from the control-lab directory.

The fixture writes an inert model-metadata artifact to a digest-pinned Distribution registry in a disposable Kind cluster. With the control off, the peer receives the same model bytes and loses signed lineage. The governed path preserves the manifest, model blob, statement, and signature. A separate peer validator reads the destination registry and checks signature, subject, source digest, and selected lineage fields. The original three grouped checks remain: control-off loss of lineage, approved lineage preservation, and refusal of missing/stale/mismatched/invalid evidence before destination writes.

The peer trust ConfigMap is created before source signing and registry publication. It contains public key bytes, a signer identity, the matching public-key fingerprint, and active state. One additional grouped check confirms that a second fixture signer can create a cryptographically valid statement for the same inert model but is refused by the peer policy before a destination manifest is written. The test then changes the approved key's policy state to withdrawn, observes the ConfigMap resourceVersion and state transition, starts a fresh verifier Pod, and confirms that a later transfer of the previously valid approved artifact is refused before destination write.

Both signing keys are generated per run in a temporary driver directory and removed when the directory closes. No private key is mounted into a Pod or included in a command payload. The peer receives only public material. Raw evidence contains only fingerprints, policy state, decisions, and no-write predicates.

The new assertion covers only a case-owned signer policy and its local withdrawal decision. It does not prove the actual producer identity, authority over production trust, remote key custody, approved business workflow, key rotation governance, or complete component/model lineage. Those remain adopter evidence. The two disposable registries are live. The replicated fixture contains inert metadata bytes.

The four grouped checks compare the exact source and destination metadata and peer trust lifecycle. The adopter procedure verifies actual signer custody and independent approval, trust publication and revocation, registry route coverage, and upstream training and promotion attestations.
