# Verify supplier-intake evidence for an approved artifact

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0604-007 --docker-context desktop-linux
```

The reference uses fictional supplier and approval records with a live Kubernetes admission boundary. The case verifies the scoped exact image and associated inventory, compares approved and refused declarations and exercises protection of approval parameters. This demonstrates technical enforcement for selected artifacts using case-owned metadata.

For adoption, identify applicable suppliers, reusable software and authorized acquisition pathways. Version the baseline criteria, communicate the applicable requirements through the approved vendor channel and retain the actual acknowledgement and reviewer decision. Evaluate risk-appropriate disclosure, support, update, licensing, integrity and component evidence. Bind the approval to the exact artifact, version and digest, plus the reviewer, scope, expiry and policy. Restrict approval writers independently. Compare approved and mismatched examples at the actual admission path and retain the exact decision and applicable exception. Recheck approval when supplier, requirements or artifact change.

[NIST SP 800-218 SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
