# SAF-K8S-0905-042 ML-BOM and lineage metadata

Run from the framework checkout:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0905-042 --docker-context desktop-linux
```

A restricted Kubernetes Job trains a fixed synthetic model. The generated
record binds the model digest to its dataset, training configuration, runtime,
Job, Pod, and Node. The test rejects a document missing the actual dataset
digest, accepts the matching record, and runs the pinned CycloneDX CLI for
schema 1.7. No third-party training dependencies are present in this fixture.

For adoption, inventory the supported model, framework and dataset paths.
Generate a BOM from a representative build, independently compare its digests
with the registered model and source records, and preserve the Job, Pod, Node,
configuration and runtime identifiers. Verify a missing or mismatched required
input fails in the actual workflow. Apply the scoped NIST mappings where the
result is used for documented component tracking, risk mapping or pedigree
validation.

CTA-2114 alignment requires authorized access to the report, exact clause and
field evidence, and an observed comparison of the selected schema and tools.
The official public description identifies the report and offers member login
or purchase. CycloneDX schema verification alone cannot establish its
alignment. Follow the open `saf-lab-0905-042.1` Bead for that source gate.

Sources [CTA-2114](https://www.cta.tech/standards/mitigating-cybersecurity-threats-in-ml-based-systems/),
[NIST AI RMF](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/) and
[NIST SP 800-53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final).
