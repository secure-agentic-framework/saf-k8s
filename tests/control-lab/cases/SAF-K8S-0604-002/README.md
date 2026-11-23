# Generate and verify an ML-BOM

```sh
python3 lab.py test SAF-K8S-0604-002 --docker-context desktop-linux
```

The fixture builds a CycloneDX 1.7 inventory for a tiny synthetic model with
declared software and training and validation datasets. The pinned official CLI
checks the schema offline. On an ARM host Docker must be able to run its pinned
amd64 image. Separate Kubernetes Jobs verify the model, dependency edge, model
card and dataset bindings. The release stores the verified inventory and inputs
in an immutable ConfigMap. A new Job reads those bytes and executes the model.

The fixture checks declared metadata and byte identity. It leaves training
attestation, rights, production lineage, infrastructure identity, model
performance and production retention to separate evidence.
