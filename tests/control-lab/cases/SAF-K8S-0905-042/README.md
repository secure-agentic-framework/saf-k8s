# SAF-K8S-0905-042

Run `python3 lab.py test SAF-K8S-0905-042`. A restricted Kubernetes Job trains
a fixed synthetic linear model. The case binds the resulting model to its input
data, training parameters, trainer and runtime versions, and actual Job, Pod
and Node metadata. It compares the accepted lineage record with a document
missing the required dataset hash and runs the pinned CycloneDX CLI against
the emitted 1.7 ML-BOM.

The fixture uses the Python standard library. CTA-2114 clause-level alignment
and adoption in a deployed training workflow require separate evidence.
