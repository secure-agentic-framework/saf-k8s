# A100 firmware evidence scope

The Google Compute Engine passthrough A100-SXM4-40GB exposed VBIOS
`92.00.45.00.03`, InfoROM image `G506.0200.00.04`, and a valid InfoROM
checksum. These are one device's inventory and health observations. NVIDIA
describes the InfoROM validation operation as reading the flash and checking
its checksums. The resulting value has no device-signed measurement or
challenge binding. [A100 inventory](../SAF-K8S-0802-008/a100-reference/firmware-inventory.json)
and [NVML device queries](https://docs.nvidia.com/deploy/nvml-api/620/api/group__nvmlDeviceQueries.html).

NVIDIA documents separate boot and firmware-update controls for specific A100
products. Its 80 GB PCIe brief identifies some boards with an additional
CEC1712 trust component and a firmware-attestation feature. The lab A100 was
a different, 40 GB SXM SKU. The cited product brief gives no evidence about
the passthrough interface of this guest.
[NVIDIA A100 80 GB PCIe product brief, Root of Trust](https://www.nvidia.com/content/dam/en-zz/Solutions/Data-Center/a100/pdf/PB-10577-001_v02.pdf#page=14).

The documented NVIDIA Attestation SDK GPU workflow requires a confidential
VM and a CC-capable H100 or later GPU. Google describes GPU device attestation
as an SPDM-backed VBIOS verification path distinct from the VM's boot and
driver verification. Authentication of the lab A100 firmware remains
unverified. [NVIDIA SDK prerequisites](https://docs.nvidia.com/attestation/attestation-client-tools-sdk/latest/gpu_and_switch_attestation.html)
and [Google Cloud Confidential VM attestation](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/attestation#gpu-based-attestation).

When using this control for a supported device, capture the exact board,
firmware component and attestation interface. Verify the trusted certificate
chain, fresh challenge, expected measurements or reference manifests, and
verifier result. Retain signed-update enforcement evidence separately where
the provider or device documents that mechanism.
[NVIDIA nonce-bound device API](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/api/group__attest.html)
and [DGX A100 secure firmware lifecycle](https://docs.nvidia.com/dgx/dgxa100-user-guide/security.html).
