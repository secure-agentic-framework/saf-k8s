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

The July 2024 SSDF Community Profile covers **generative AI and dual-use foundation model development**, including data sourcing, design, training, fine-tuning, evaluation, and integration of these models into other software. AI system deployment and operation and data governance outside model development fall outside its scope. NIST directs organizations to apply the Profile alongside SSDF v1.1 and select tasks based on their role, risks, and applicability. [NIST SP 800-218A, §§1.1–1.2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf#page=10) [NIST SP 800-218A, §2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf#page=12)

The case uses these exact task identifiers from the final Profile's Table 1:

| Task | NIST task (short description) | Case coverage |
| --- | --- | --- |
| PO.3.3 | Configure tools to generate artifacts of support for secure development practices. | Schema and fixture evidence links are checked. NIST's note gives dataset integrity/provenance attestations as an AI example. No organizational toolchain is assessed. |
| PO.5.1 | Separate and protect each development environment. | A versioned environment record is linked to the run. The separate native authorization case tests namespace API isolation and least privilege for named objects. |
| PS.2.1 | Make software release integrity verification information available to acquirers. | A fixture hash and release reference are checked; signatures, acquirer access, and production release integrity are not tested. |
| PS.3.1 | Securely archive release files and supporting data. | The synthetic record contains versions and process metadata. No archive, retention system, or actual training process is exercised. |
| PS.3.2 | Collect, safeguard, maintain, and share provenance data for release components. | The fixture links one dataset, one run, one artifact, and one release; a mismatched release link is rejected. There is no trusted attestation, identity, registry, or production consumer. |
| PW.3.2 | Track known training-data provenance and document data whose provenance is unknown. | The known-source fixture branch and its version/digest linkage are checked. A missing source stays documented and blocks fixture validation. |

The task names and AI-specific additions are in the [official NIST SP 800-218A PDF, Table 1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf#page=18) (PO.3.3 and PO.5.1), [page 12](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf#page=20) (PS.2.1–PS.3.2), and [pages 14–15](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf#page=22) (PW.3.1–PW.3.3). The fixture covers bounded reference validation, integrity-before-use, and namespace API authorization. Organizational conformance calls for evidence across applicable activities.

## Control claims still requiring review

- “Training runs as builds” is a useful local analogy for recording training-process provenance. The Profile discusses documenting the training process and tracking model/component/pipeline provenance, but does not define training runs as software builds. Treat the analogy as a proposed local mapping, not a NIST statement.
- “Model weight integrity as software integrity” also needs a bounded mapping. The Profile has AI-specific additions concerning model weights and configuration parameters, including PS.1.1 and PS.1.3, and release integrity at PS.2.1. This case contains no model weights and does not validate those protections.
- For the team's governed model-development processes, record the Profile edition, task ID, applicability and rationale, SAF-K8S control IDs, workflow owner, observed evidence, and approved disposition. Include tasks where the team has evidence of partial coverage and record unresolved gaps with owners and review dates. The case's fixed task list describes the fixture; each adopter selects and approves its applicable tasks.
- The PW.3.1 supplement rejects changed or missing synthetic partitions before feature publication and verifies the expected output from the approved partition. Data-poisoning and bias analysis, signed releases, model weight protection, and operation of adopted pipelines need their own evidence.

The Jobs use only synthetic fixture metadata.

## PO.5.1 development-environment API authorization

The [NIST SP 800-218A table](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf#page=18)
covers development-environment separation and least privilege. This case exercises
one Kubernetes API authorization boundary using two fixture namespaces and two
ServiceAccounts. The temporary ClusterRole is limited to GET and LIST on two
named, immutable marker ConfigMaps. The developer first reads both under a
cross-namespace binding. Removing that binding causes the developer to receive
403 on protected GET and LIST while own reads continue to work. An approved
reader still retrieves and lists the same protected object.

The three Jobs project 600-second ServiceAccount tokens and keep credentials
out of the evidence. Their results match the exact Job-owned Pods and immutable
object UIDs. The developer's mounted expectations supply only the protected
object's identity, and the harness verifies its inert marker when access succeeds.
Follow-up adoption evidence covers the actual environment inventory, other
protection boundaries, policy ownership, and applicable operating practices.

From the framework checkout use `python3 tests/control-lab/lab.py test SAF-K8S-1006-008 --docker-context desktop-linux`.
Include the adjacent SAF-K8S-0906-002 and SAF-K8S-0907-005 cases for the existing
integrity checks. Kubernetes requires the exact `metadata.name` selector for
resource-name-scoped list requests. [Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-resources)
