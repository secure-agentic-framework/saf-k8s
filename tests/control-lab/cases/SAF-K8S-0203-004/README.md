# SAF-K8S-0203-004 — Secure Boot and the firmware signer allowlist

```sh
python3 lab.py test SAF-K8S-0203-004 --docker-context desktop-linux
```

A restricted Kind Job starts isolated QEMU guests with AAVMF virtual UEFI.
The same owned EFI program runs unsigned when enforcement is off and is
refused when enforcement is on. A copy signed by the enrolled signer runs
with Secure Boot reported active. A second, differently signed copy is
refused under the first policy. With a separately prepared variable store
that authorizes only the second certificate, the replacement runs and
firmware refuses the original signer. The fixture retains the two public
certificate fingerprints and the exact firmware and toolchain hashes.

This exercises firmware authorization of an EFI application across two
fixture trust policies. The test prepares the stores offline. Evidence for
a supported in-place policy update or revocation, subsequent boot stages,
physical or provider firmware, and measured boot remains profile-specific.

## Verify deployment applicability and evidence

1. Bind each governed pool to the exact OS image, provider or hardware
   platform, firmware release, Secure Boot capability, trust provisioning
   owner, and approved exception. Map each required boot stage and its
   verifier and trust anchor. Track fallback and recovery paths.
2. Retain firmware-reported Secure Boot state and setup mode, authorized
   and revoked signer or hash identifiers, and OS/vendor evidence for the
   bootloader, kernel and any later in-scope stages. Use the provider’s
   supported evidence for managed hardware. Verify that each result
   identifies the tested node profile and current firmware and OS build.
3. In controlled staging, boot an approved signed test image and observe
   refusal of an unauthorized marker at the stage under review. Exercise
   the system’s supported trust update and recovery path, with approved
   public keys and evidence that superseded trust is no longer accepted
   where removal is required.
4. Where the profile requires measured boot, verify the signed attestation,
   freshness challenge and approved measurements against the same booted
   versions. Keep firmware authorization, later-stage verification and
   measured state distinct in the evidence packet.

[UEFI Secure Boot specification](https://uefi.org/specs/UEFI/2.11/32_Secure_Boot_and_Driver_Signing.html) ·
[QEMU Arm virt platform](https://www.qemu.org/docs/master/system/arm/virt.html) ·
[Debian firmware variable utility](https://manpages.debian.org/trixie/python3-virt-firmware/virt-fw-vars.1.en.html)
