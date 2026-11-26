# Verify required CI evidence at promotion

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0606-011 --docker-context desktop-linux
```

The disposable API rejects release records with required checks failed, missing or skipped, and rejects artifact, source, test or policy revision mismatches. A separate Job evaluates the fixed public fixture bytes, computes the exact artifact digest and submits a record. Kubernetes authorization refuses an unbound writer. The native promotion policy also refuses an otherwise authorized writer's mismatched policy record. The API separately stores the matching immutable record. The check-type status inputs are synthetic in this reference. The independent scan-report example proves a real pinned scanner and its signed input boundary.

For adoption, inventory actual required checks by artifact and release stage. Restrict evidence writers and promotion authority independently. Verify producer identity and native scanner or CI receipts, and bind the applicable required results to the exact artifact and source, check and policy revisions. Compare approved and failed cases at the effective release point, including an unapproved writer and wrong artifact or policy binding. Review exception authority, scope, expiry and evidence. Test source-control push protection at the repository boundary, and verify the released and deployed digests independently. Retain the producer, decision and approved exception evidence.

[Signed scanner-report reference](https://github.com/secure-agentic-framework/saf-k8s/blob/915da0715523deb33ac093e918b63ecb85f040d8/tests/control-lab/verified/SAF-K8S-0601-008.json) · [Protected Git ref reference](https://github.com/secure-agentic-framework/saf-k8s/blob/83c0ba792c56d925793aa8ee2a5acf9b58b2654f/tests/control-lab/verified/SAF-K8S-0606-024.json)
