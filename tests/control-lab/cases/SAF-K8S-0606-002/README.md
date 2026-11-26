# Verify isolated build-runner execution

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0606-002 --docker-context desktop-linux
```

The disposable Jobs compare Restricted admission, scoped egress and a short-lived projected identity authorized to read one named ConfigMap. The default token mount is disabled. The governed runner reaches the approved input and refuses the separate comparison paths. The Job and Pod are removed by the TTL controller. Its replacement starts with a fresh writable workspace and packages the verified input.

For adoption, identify each CI execution profile and exact job-to-environment binding. Verify the effective admission policy and privilege configuration, distinct runner identity, network reachability and each allowed dependency. Inspect how job-local and retained storage, caches, logs and runner registration are cleaned or reused. Confirm the deployed token or credential issuer, scope, lifetime and revocation at its accepting service after the job. An independently tested Kubernetes example shows refusal of a bound credential after its test identity is removed. Verify external providers, signing authority and registry credentials at their actual boundaries. Record the authorized source, job identity, exact artifact, cleanup, exceptions and scoped credential outcome.

[Separate bound credential reference](https://github.com/secure-agentic-framework/saf-k8s/blob/verified-control-tests/tests/control-lab/verified/SAF-K8S-0405-003.json) · [NIST SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
