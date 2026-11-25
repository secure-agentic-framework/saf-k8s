# SAF-K8S-1005-028 — Forensic preservation of AI metadata

```sh
python3 lab.py test SAF-K8S-1005-028 --docker-context desktop-linux
```

The case uses the pinned Kubernetes v1.36.1 Kind node image and two synthetic ConfigMaps in a case-owned namespace. One stores an approved mock model-read record; the other stores an approved mock training-lineage record with fabricated labels and an inert SHA-256 digest of a label string. No model, dataset, credentials, external feed, or network target is used. No workload image is needed.

## Observations

- **Red:** the API returns both source records, while a deliberately model-access-only capture omits training lineage. The evidence directory records the missing record kind.
- **Green:** the case captures both record payloads as raw bytes from Kubernetes API responses, writes SHA-256 sidecars and a completeness manifest, removes the source ConfigMaps to model cleanup, and verifies that both source records are absent while both captured byte streams remain intact and hash-matched.
- **Positive:** the saved model-read record still says `approved` and `read`; the saved lineage record still says `approved` and retains its fabricated labels and inert digest. The verification confirms that the bundle contains no model or dataset content.

The evidence files are synthetic metadata only: `model-read-record.json`, `training-lineage-record.json`, their `.sha256` sidecars, `preservation-manifest.json`, and `incomplete-capture.json`. The runner's normal command transcript also contains only the fixture ConfigMaps and their metadata.

## Coverage and unresolved claims

This demonstrates a narrow capture, completeness check, integrity check, and survival of a local evidence copy after deleting two case-owned Kubernetes source objects. It does not establish that a production registry, model CRD, audit backend, experiment tracker, or training pipeline emits complete records; that a responder identifies all relevant artifacts; or that a production evidence repository provides access control, durable retention, tamper resistance, independent custody, or legally sufficient handling. It also does not determine whether an actual model, training run, or dataset was impacted. Those source and deployment claims remain unverified by this fixture.

Kubernetes audit records cover API-server activity according to the configured audit policy and backend; they do not by themselves establish that application-level model reads or training lineage were emitted or captured. The fixture models those as separate records for that reason. Kubernetes documents the audit policy, log/webhook backends, and log rotation behavior in its [v1.36 Auditing guide](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/). The node image digest matches the [Kind v0.32.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0). NIST's [SP 800-86](https://csrc.nist.gov/pubs/sp/800/86/final) provides general forensic incident-response guidance. NIST's [AI Risk Management Framework 1.0](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf) discusses maintaining training-data provenance and supporting attribution; these sources motivate the bounded fixture but do not validate any production implementation.

The red arm uses a case-owned read-only RBAC identity. The lineage record exists
but is forbidden to that identity. Granting exact-name access closes the collection
gap while keeping an existing unapproved comparator forbidden.

## Verify an adopting implementation

Map real model-read and training-lineage events to
authenticated workload, pipeline, artifact, and deployment IDs. Verify
collection completeness and least privilege, preserve records through source
cleanup, and recheck integrity and independent retrieval from the approved
retention store. Document audit gaps, retention/immutability controls, custody
and owner review; keep real model or dataset contents out of the evidence
bundle.
