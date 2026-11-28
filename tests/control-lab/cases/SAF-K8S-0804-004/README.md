# SAF-K8S-0804-004 runtime budget and synthetic qualification deferral

The original three checks remain unchanged. They exercise Kubernetes RuntimeClass overhead accounting against a namespace quota, then run the same inert payload with and without declared `runc` overhead after the quota is adjusted. The elapsed times are local fixture observations only.

An additive native admission workflow independently reads the completed overhead-profile Pod, its UID, runtime class, declared overhead, image ID and output; it binds those facts and the original baseline result digest into a synthetic immutable deferral record. A reviewer identity is required. Incomplete records, an adoption claim while protected measurements are unavailable, and an observer submission are denied. The accepted record requires a durable admission compensating control and explicit reassessment criteria. A parameterized ValidatingAdmissionPolicy then denies Pod admission for exactly `fixture-with-overhead` and admits the baseline comparator, both by server dry-run. This is a software workflow demonstration over inert test inputs, not an approval or readiness conclusion for any actual confidential AI workload.

The fixture uses the digest-pinned Python image already present in the case. It tests neither a TEE nor a confidential runtime, hardware/device attestation, protected workload performance, training/inference capacity, cryptographic key custody, or deployment recovery. Those facts remain subject to supported platform and adopter evidence.


## Live Confidential Space reference

The same digest-pinned CPU workload completed three measurements on a standard N2D VM and three on confidential N2D VMs. All runs processed the same inputs and produced the same inference digest. The evidence records timing and the resulting bounded lab readiness decision.

[Shared reproducer and evidence](../../references/gcp-confidential/README.md)
