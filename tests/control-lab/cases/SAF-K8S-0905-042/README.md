# SAF-K8S-0905-042 ML-BOM and lineage metadata

CTA-2114 (November 2025), Sections 5 and 8.8, recommends BOM records for
model lineage, dataset provenance, hyperparameters, and training environment
configuration. The sections also address linked attestations and BOM change
tracking. SAF requires exact versions and training infrastructure identity.
This case represents its observations with CycloneDX 1.7, SAF properties, and
Kubernetes object identifiers.

Run from the framework checkout:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0905-042 --docker-context desktop-linux
```

A restricted Kubernetes Job trains a fixed synthetic model. The generated
record binds the model digest to its dataset, training configuration, runtime,
Job, Pod, and Node. The test rejects a document missing the actual dataset
digest, accepts the matching record, and runs the pinned CycloneDX CLI for
schema 1.7. No third-party training dependencies are present in this fixture.

## CycloneDX 1.7 fields in this test

| Evidence | Location in the generated BOM |
| --- | --- |
| Inert model, training task and referenced dataset | `metadata.component` and its `modelCard.modelParameters` |
| Actual fixture dataset digest and classification | The data component's `hashes` and `data[].classification` |
| In-BOM model-to-dataset relationship | The model's `datasets[].ref` and the BOM's `dependencies` |
| Model and training configuration digests, exact runtime, Job, Pod and Node | Case-defined `saf:` properties on the model component |

The pinned CycloneDX CLI v0.33.1 validates structure against schema 1.7. The
fixture independently compares expected values with the observed Job output.
The reported Python version identifies the fixture runtime. Verify the
actual ML framework and its version in the adopted workflow. [CycloneDX 1.7
JSON reference](https://cyclonedx.org/docs/1.7/json/), [CycloneDX AI/ML-BOM
Guide](https://www.cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-AI-ML-BOM-en.pdf),
[CycloneDX CLI v0.33.1](https://github.com/CycloneDX/cyclonedx-cli/releases/tag/v0.33.1).

For adoption, inventory the supported model, framework and dataset paths.
Generate a BOM from a representative build, independently compare its digests
with the registered model and source records, and preserve the Job, Pod, Node,
configuration and runtime identifiers. Verify a missing or mismatched required
input fails in the actual workflow. Apply the scoped NIST mappings where the
result is used for documented component tracking, risk mapping or pedigree
validation.

The lab result covers the synthetic BOM, its observed inputs, and schema
validation. For production use, verify the actual ML framework versions,
training-data sources, infrastructure approvals, model and data integrity
controls, and linked training attestations.

Sources [CTA-2114](https://www.cta.tech/standards/mitigating-cybersecurity-threats-in-ml-based-systems/),
[NIST AI RMF](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/) and
[NIST SP 800-53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final).
