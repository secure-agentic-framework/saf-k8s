# Verify approved build toolchain bytes before execution

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0606-009 --docker-context desktop-linux
```

An unchecked Job executes the changed public fixture tool. Under the digest check, the same bytes are refused and the approved immutable bytes execute with the default token mount disabled. This demonstrates the selected tool's verification boundary before execution.

For adoption, inventory tools and toolchain entrypoints by actual version and immutable digest. Record the authorizing provenance, verification policy, delivery source, tool owner and update and exception procedure. On each selected CI execution path, compare an approved tool with a harmless changed tool and verify execution occurs only after approval. Record the exact input, expected digest, Job and policy revision, and decision. For applicable SSDF work, map the full chosen practice set to its owner, evidence and organizational process. Evaluate coverage, operation and maintenance separately from the demonstrated tool check.

[NIST SP 800-218 SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
