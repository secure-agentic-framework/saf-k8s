# Google Cloud Confidential Space reference

This lab uses a digest-pinned non-root container on an AMD SEV N2D VM. It
runs a deterministic synthetic inference and exercises a real key-protected
fixture through Google Cloud Attestation, Workload Identity Federation,
Security Token Service, and Cloud KMS. The protected artifact is an inert
marker. The workload prints digests, timing, and normalized decisions.
The run retains no attestation token, access token, key, or plaintext in
public evidence.

The five control receipts use one shared workload.

- **0804-001** exercises attested protected resource use on the CPU profile.
- **0804-002** tests a fresh challenge, rejection of the wrong challenge, and
  rejection when only the same token's signature changes. The signed original
  succeeds on both sides of that comparison.
- **0804-004** compares the same image and inference output on standard and
  confidential N2D instances. The sample covers one CPU workload and one
  region. Whole-VM startup and the resource API are outside the timed segment.
- **0804-005** tests Cloud KMS Decrypt with an approved attested principal.
  A fresh request initially succeeded after the grant was removed. A later
  fresh request still passed STS and Cloud KMS returned HTTP 403. Account for
  IAM propagation and previously released data in an incident procedure.
- **0804-006** denies the unapproved image digest, allows the approved update,
  checks the expected plaintext digest, and separately rejects tampered
  ciphertext through the same Cloud KMS key.

## Reproduce the reference

1. Use a disposable lab account or project with a supported AMD SEV zone.
   Create a dedicated Artifact Registry repository, workload service account,
   and workload identity pool. Give the VM service account only the permissions
   needed to fetch the lab image and request attestation. Grant decryption
   directly to the approved federated principal for the selected key, scoped
   to the immutable image digest.
2. Build `workload/` for Linux amd64. Pass the pool project number, pool ID,
   OIDC provider, expected plaintext digest, and lab key resource path as
   build arguments. The resource path identifies the key and contains no key
   material. The two build variants must yield different image digests. Use
   the same image digest and `CPU_ROUNDS` for the matched baseline.
3. Pin the production Confidential Space image and enable AMD SEV. Set the
   immutable workload image, `tee-nonroot-container=true`, and the serial
   output setting. Use the exact launcher environment override names from
   the Dockerfile. Feed a fresh challenge through `CHALLENGE_NONCE`; set the
   relying-party condition to verify that challenge, the profile, workload
   identity, and image digest. Set the allowed audience to the workload's
   custom audience. Do not send confidential material in VM metadata.
4. Exercise the permitted workload and capture its normalized receipt.
   Use a fresh VM for each denied comparator. The workload accepts
   `EXPECT_ACCESS=false` with `NEGATIVE_CASE=attribute_condition`,
   `invalid_signature`, or `resource_forbidden`. For the first case,
   supply a different image or challenge. For the last, remove the KMS
   role from the approved identity and retain attempts during propagation.
   Rotate the approved digest and demonstrate authorized access again.
5. Run the same CPU segment on a standard N2D VM in `MODE=cpu-only` and
   preserve the output match. Independently test the original and altered
   ciphertext on the lab key. Record the production profile limits and
   the workload-specific decision about adopting the profile.
6. Set an automatic VM deletion deadline and an auto-deleting boot disk
   when provisioning. Remove the test VM and disk, any networks, images,
   storage, access roles and identity resources. If using a disposable
   import-only software Cloud KMS key with a zero destruction delay,
   verify the key version reaches `DESTROYED`. Check deployed organization
   policy before selecting the key destruction schedule.

Port 1 serial output can contain kernel messages spliced into application
records. `read-console.py` removes those timestamped console records,
then uses a JSON decoder to validate the reconstructed workload records.

Use the case-by-ID checker to review the saved sanitized evidence.

```bash
python3 tests/control-lab/references/gcp-confidential/check-reference.py SAF-K8S-0804-002
```

- [CPU reference receipt](cpu-reference.json)
- [Google Cloud Attestation](https://docs.cloud.google.com/confidential-computing/docs/attestation)
- [Confidential Space attestation assertions](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/attestation-assertions)
- [Direct access to protected resources](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/create-grant-access-confidential-resources)
- [IAM policy propagation](https://docs.cloud.google.com/iam/docs/access-change-propagation)
