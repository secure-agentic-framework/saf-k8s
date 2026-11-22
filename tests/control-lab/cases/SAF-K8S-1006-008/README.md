# SAF-K8S-1006-008 — Synthetic AI development evidence references

Run from the control lab with a disposable Docker-backed Kind cluster:

```sh
python3 lab.py test SAF-K8S-1006-008 --docker-context desktop-linux
```

This case uses Kubernetes v1.36.1 and digest-pinned `kindest/node` and Python images. It creates four native Jobs in the lab's test namespace. The Jobs only parse checked-in synthetic JSON and hash inert fixture strings; they do not train, load, call, modify, or evaluate a model. The dataset content is synthetic, the training run is explicitly `not_performed`, and the artifact is metadata only with `weights_present: false`. Every external-looking reference uses the reserved `example.invalid` domain.

Each Job has its own status and pod log. The case retains the raw Job object, Pod list, and log beside the fixture used for that scenario. The outcomes are:

- **Green:** a schema-versioned development fixture has matching dataset, training-run, environment, artifact, and release references. Its result says only `fixture_consistent`; governance and actual operation remain `unknown`, and `asserts_compliance` is false.
- **Red:** a deliberately mismatched release artifact version and digest cause the checker Job to fail with `REJECT release_provenance_mismatch`.
- **Positive:** a synthetic AI system deployment/operation record is labeled `out_of_profile`. The checker preserves unknown governance and operation and makes no compliance judgment.

## NIST scope and source review

The corrected control distinguishes model development and integration from deployment and operations. The final July 2024 publication is an SSDF Community Profile for **generative AI and dual-use foundation model development**. Its scope includes data sourcing, design, training, fine-tuning, evaluation, and integration of AI models into other software. It explicitly puts AI system deployment and operation, and the rest of the data governance/management lifecycle, outside its scope. NIST says the Profile supplements and is to be used with SP 800-218; it does not replace the SSDF baseline. See [NIST SP 800-218A, §§1.1–1.2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf#page=7) and [NIST SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final).

The case uses these exact task identifiers from the final Profile's Table 1:

| Task | NIST task (short description) | Case coverage |
| --- | --- | --- |
| PO.3.3 | Configure tools to generate artifacts of support for secure development practices. | Schema and fixture evidence links are checked. NIST's note gives dataset integrity/provenance attestations as an AI example. No organizational toolchain is assessed. |
| PO.5.1 | Separate and protect each development environment. | A versioned environment record is linked to the run. Isolation and protection are explicitly metadata-only and not assessed. |
| PS.2.1 | Make software release integrity verification information available to acquirers. | A fixture hash and release reference are checked; signatures, acquirer access, and production release integrity are not tested. |
| PS.3.1 | Securely archive release files and supporting data. | The synthetic record contains versions and process metadata. No archive, retention system, or actual training process is exercised. |
| PS.3.2 | Collect, safeguard, maintain, and share provenance data for release components. | The fixture links one dataset, one run, one artifact, and one release; a mismatched release link is rejected. There is no trusted attestation, identity, registry, or production consumer. |
| PW.3.2 | Track known training-data provenance and document data whose provenance is unknown. | The known-source fixture branch and its version/digest linkage are checked. A missing source stays documented and blocks fixture validation. |

The task names and AI-specific additions are in the [official NIST SP 800-218A PDF, Table 1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf#page=10) (PO.3.3 and PO.5.1), [page 12](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf#page=12) (PS.2.1–PS.3.2), and [pages 14–15](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf#page=14) (PW.3.1–PW.3.3). The checker validates fixture references and hashes only. It does not establish that any Profile task is implemented or that an organization conforms.

## Control claims still requiring review

- “Training runs as builds” is a useful local analogy for recording training-process provenance. The Profile discusses documenting the training process and tracking model/component/pipeline provenance, but does not define training runs as software builds. Treat the analogy as a proposed local mapping, not a NIST statement.
- “Model weight integrity as software integrity” also needs a bounded mapping. The Profile has AI-specific additions concerning model weights and configuration parameters, including PS.1.1 and PS.1.3, and release integrity at PS.2.1. This case contains no model weights and does not validate those protections.
- The control calls for mapping these practices to SAF-K8S controls, while its Related Crosswalks section says there are no rows. No SAF-K8S control IDs or validated crosswalk are asserted here; that mapping remains unresolved.
- The pinned original mentions teams that deploy AI workloads. The corrected wording follows the model-development scope. Deployment/operation governance is intentionally unknown in this case.
- The fixture only proves deterministic local consistency and rejection of a wrong release reference. It does not evaluate training-data poisoning, bias, homogeneity, or tampering under PW.3.1; verify signatures; inspect model weights; test an actual pipeline; or establish governance, authorization, production operation, or Kubernetes-wide coverage.

The Jobs use only synthetic fixture metadata.
