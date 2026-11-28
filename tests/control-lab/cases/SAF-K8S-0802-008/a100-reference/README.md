# A100 signed NVIDIA modules and measured boot

The reference ran on a dedicated Google Compute Engine A2 Spot guest with an
A100-SXM4-40GB, Ubuntu 22.04, kernel `6.8.0-1074-gcp`, and Ubuntu-packaged
NVIDIA driver `580.178.04`. The kernel ran in integrity lockdown with Secure
Boot enabled. Both loaded NVIDIA modules reported the expected version and no
unsigned-module taint. The collector compared each installed module's appended
signature with the Canonical package-owned signature bytes, and checked the
signing key and active module version.

The separate operator-side check correlated the provider's startup, early
and late Shielded VM integrity events with the exact instance identity, guest
boot time, and signed-module capture. Both integrity evaluations passed on the
same boot counter. The retained evidence represents one completed boot on one
host. The Spot VM was preempted during supplementary Kubernetes testing.
Revoked-key rejection, continuous enforcement over later boots, and the
Kubernetes admission decision using this host's evidence remain open.
The companion [firmware inventory](firmware-inventory.json) records VBIOS and
InfoROM checks. The InfoROM checksum is a health check. Firmware authentication
requires separate evidence.

## Replay

Use a disposable A100 Linux guest whose hostname matches `saf-a100-[0-9]{10}`.
Enable Shielded Secure Boot, vTPM, and integrity monitoring and install the
matching Ubuntu NVIDIA package set. Load the distribution modules normally
and verify the GPU is ready before collecting.

```sh
sudo python3 verify-loaded-signed-modules.py signed-modules.json
```

On the same guest, capture its ID from the Google Compute Engine metadata
server using `Metadata-Flavor: Google`, the `btime` in `/proc/stat`, and the
current `/proc/sys/kernel/random/boot_id`. Save them as three lines in
`boot-identity.txt` with `instance_id=` and `boot_epoch_s=` prefixes on the
first two lines. Use the matching instance description from `gcloud compute
instances describe --format=json` and use `gcloud logging read` to collect
`compute.googleapis.com/shielded_vm_integrity` events filtered to that
instance ID and boot interval. Keep those raw provider and identity exports
private. Run the binder on the operator's machine.

```sh
python3 bind-shielded-boot.py instance.json integrity-events.json \
  boot-identity.txt signed-modules.json reviewed-boot.json
```

The retained [module receipt](signed-modules-boot1.json) and
[correlated boot review](bound-boot1.json) omit the instance ID and full
measured-boot logs. This evidence accompanies the portable control case.

- [Shielded VM integrity monitoring](https://docs.cloud.google.com/compute/shielded-vm/docs/integrity-monitoring)
- [Ubuntu Secure Boot](https://documentation.ubuntu.com/security/security-features/platform-protections/secure-boot/)
