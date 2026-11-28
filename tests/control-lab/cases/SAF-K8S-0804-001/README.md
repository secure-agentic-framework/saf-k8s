# SAF-K8S-0804-001 Modeled confidential placement gate

The API rejects the ordinary runtime and missing placement on a labeled fixture namespace. The matching request stays Pending until the owned Kind node receives the modeled approval label. The exact same Pod then becomes Ready.

Both fixture classes resolve to runc and use only a CPU workload. The test exercises admission and scheduling only. Hardware TEE, memory protection, confidential GPU behavior and attestation require separate deployed evidence.

## Separate CPU and GPU evidence before use

The case also verifies selected evidence from a public Azure H100 reference
capture. A Kind Job in a separate restricted verifier namespace independently verifies the AMD SEV-SNP report
and its Azure HCL runtime claims, and the NVIDIA H100 SPDM transcript and its
recorded challenge. The runner downloads the AMD and NVIDIA trust anchors from
their publishers separately from the digest-pinned capture. The CPU appraisal
also checks the archived AMD CRL at the fixed capture time. The retained result
contains verdicts and the archive digest. The case does not publish raw
attestation data, certificate subjects, VM identifiers or nonces.

The authenticated HCL claims show Secure Boot off and no match to the recorded
CPU challenge. The signed GPU challenge also does not match the fixture's
required SHA-256 binding to the exact HCL report. This binding rule is specific
to the fixture. The normal placement policy first accepts a dry run for an
inert Pod. A parameterized Kubernetes ValidatingAdmissionPolicy then rejects
an actual create for the same Pod name using the immutable archive decision.
An independent API read verifies that the Pod was never created.

The hardware evidence is historical. The test covers neither a current
challenge and revocation decision nor real workload or device assignment.
Use the standard control-ID test with Go and curl. The first build fetches the
public capture, independent vendor roots and Go module checksums. The Job uses
no live verifier or vendor service.

- [Published Azure capture and its limitations](https://untrustsecurity.com/evidence/#azure-ncc-h100-v5--sev-snp-hcl-report-vtpm-quote-and-nvidia-h100-attestation)
- [Microsoft guest attestation report format](https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design)
- [AMD VCEK trust and KDS specification](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/57230.pdf)
