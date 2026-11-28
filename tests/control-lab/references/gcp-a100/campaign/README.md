# Staged A100 replay for the remaining hardware cases

The bundle is assembled on the operator workstation before a separately
authorized rental. It includes the reviewed fixture sources, signed-driver
bootstrap, exact K3s and NVIDIA runtime pins, and the case-by-ID entrypoint for
the existing disposable Google Cloud guest. The guest runner uses the bundle
manifest digest as its input pin and rechecks each file before dispatch.

The [workstation staging verification](bootstrap-staging-verification.json)
covers the pinned K3s binary, release installer, and NVIDIA device-plugin
manifest. The [earlier bundle receipt](staging-verification.json) records the
Kind monitor smoke test. The full guest workflow requires an A100.

The [package preflight](package-availability.json) records the exact public
Jammy and NVIDIA package URLs and a successful amd64 APT dependency simulation
for the kernel retained from the prior guest.

## Stage the bundle

Use the published SAF-K8S `verified-control-tests` checkout with the source revisions recorded in
`prepare-bundle.py`, and Go 1.26.8 and Zig 0.14.0. Start from this directory on the workstation.

```sh
python3 -B prepare-bundle.py --framework /absolute/path/to/saf-k8s-checkout \
  --output /absolute/private/path/a100-guest
```

The builder fetches and verifies the three public bootstrap assets before
sealing the bundle. An already-downloaded directory with the exact `k3s`,
`install-k3s.sh`, and `nvidia-device-plugin.yaml` files can be reused with
`--bootstrap-assets /absolute/private/path/release-inputs`. Rebuilding with the
same inputs produces an identical manifest. Allow about 80 MB of additional
bundle space for these files.

Keep the printed manifest digest on the workstation. The exact PodResources
executable reproduces the earlier hardware run. The allocator uses the same
128 MiB CUDA source with reproducible stripped build options. Its SHA-256 is
separate from the allocator used in the earlier run. Both accepted hashes are
explicit in readiness, and the catch-and-hold check requires the same hash on
the new profile, in the copied file's readback, and when it finishes.

Transfer only this staged directory to the approved VM with its existing access
mechanism. Use root-owned guest files, a private root-owned attempt parent,
and one new attempt directory for each invocation. The case code releases its
owned port-forward processes. Transfer each completed attempt to private
operator storage before initiating the next phase or reboot. Keep raw evidence,
provider instance JSON and boot identities there. Export only reviewed normalized
receipts for the SAF-K8S repository.

## Guest checks

From the staged guest directory, verify the manifest and then bootstrap the
test stack. Substitute the manifest digest printed by the workstation and an
existing private parent for the attempt directories.

```sh
sudo python3 -B run-case.py --manifest-sha256 "$manifest_digest" verify-bundle
sudo python3 -B run-case.py --manifest-sha256 "$manifest_digest" bootstrap \
  --run-dir /var/tmp/saf-hardware/bootstrap-1
sudo python3 -B run-case.py --manifest-sha256 "$manifest_digest" capture-boot \
  --run-dir /var/tmp/saf-hardware/boot-1
sudo python3 -B run-case.py --manifest-sha256 "$manifest_digest" test SAF-K8S-0805-003 \
  --run-dir /var/tmp/saf-hardware/hold-1
```

Bootstrap verifies the release files and separately checks the installed binary
and responding API version. K3s uses the staged binary and runs the local
installer with `INSTALL_K3S_SKIP_DOWNLOAD=true` after the NVIDIA runtime is
available. A partial retry reuses an exact executable. A conflicting binary
stops bootstrap before installation. The guest needs access to the configured
signed APT repositories and runtime image registries.
[K3s local installation instructions](https://docs.k3s.io/installation/airgap)
and [the version-pinned release](https://github.com/k3s-io/k3s/releases/tag/v1.36.6%2Bk3s1).

Reproduce the local bootstrap checks from this directory. The installer smoke
uses a disposable, network-disabled Linux container and checks the generated
service unit and exact binary reuse.

```sh
python3 -B bootstrap-assets-test.py
bash bootstrap-container-smoke.sh /absolute/private/path/a100-guest "$manifest_digest"
```

The hold test uses the reviewed driver, exporter image and workload/device
binding, and requires current Prometheus and Alertmanager evidence for the
exact run. It records the immutable hold while the bounded allocation is
alive. The separately authorized comparison approval uses only an inert
record. The runner proves denial and non-persistence for the real hold's
escalation request and validates the comparison in dry-run. A passing
receipt also requires allocator release, direct framebuffer recovery,
removal of the temporary monitoring and approval resources, and preservation
of the hold. Export the threshold, admission, release, and final receipts
from the attempt directory. An interrupted attempt may leave partial evidence.

To reproduce the monitor-only check on local Kind, use the same built
bundle with synthetic input. The receipt covers the monitor join and rejected
mismatched captures. The guest case above supplies hardware and response
evidence when it completes.

```sh
python3 -B hold-binding-smoke.py --bundle /absolute/private/path/a100-guest \
  --output /absolute/private/path/hold-monitor-smoke.json
```

Run the visibility case while the whole-GPU fixture is idle and can report a
measured zero. Its private namespace contains a Prometheus, Alertmanager and
receiver. Three jobs start against the exact validated DCGM exporter. The
case changes one job to an intentionally missing metrics path, then removes
another job. It requires separate alerts for HTTP 404 and target absence and
keeps the healthy job observing a fresh zero. The DCGM deployment and its
original monitor are read-only inputs. Each checkpoint rechecks the PodResources
device, the workload and the exporter. Export the two phase checkpoints, final
receipt and journal. Kind validated the same transition contract with HTTP
fixture telemetry. A live run is required for the device-specific result.
[NVIDIA 4.8.4 exporter HTTP routing](https://github.com/NVIDIA/dcgm-exporter/blob/fafd15114805/internal/pkg/server/server.go#L99-L131)

```sh
sudo python3 -B run-case.py --manifest-sha256 "$manifest_digest" test SAF-K8S-0805-001 \
  --run-dir /var/tmp/saf-hardware/visibility-1
```

For the signed-boot case, use [the provider binder and admission inputs](../candidate/signed-admission.md).
Capture and export the reviewed first boot before an authorized reboot on the
same VM. After reboot, run `capture-boot` again in a new attempt directory and
bind both new provider integrity decisions. The admission runner requires
both separately reviewed boot/module pairs and checks the current pair against
the guest and Kubernetes Node. The first capture must precede the second
startup. If requesting MIG requires a reboot and the whole-GPU observations
are exported, use that reboot for the second signed capture.

```sh
sudo python3 -B run-case.py --manifest-sha256 "$manifest_digest" test SAF-K8S-0802-008 \
  --first-boot-review /root/reviewed/boot-1.json --first-modules /root/reviewed/modules-1.json \
  --boot-review /root/reviewed/boot-2.json --modules /root/reviewed/modules-2.json \
  --run-dir /var/tmp/saf-hardware/signed-admission-1
```

Finish the whole-GPU observations and export their receipts before requesting
MIG. A pending result is a checkpoint for an operator-controlled guest reboot.
Use [the physical MIG procedure](../candidate/mig-placement.md) for supported
current/pending state and the independent boot capture. Keep the same-boot reservation when retrying
configuration and use a fresh attempt directory. Preserve the hashed
preparation receipt alongside the live placement proof.

```sh
sudo python3 -B run-case.py --manifest-sha256 "$manifest_digest" request-mig \
  --run-dir /var/tmp/saf-hardware/mig-request-1
sudo python3 -B run-case.py --manifest-sha256 "$manifest_digest" configure-mig \
  --run-dir /var/tmp/saf-hardware/mig-prepare-1
sudo python3 -B run-case.py --manifest-sha256 "$manifest_digest" test SAF-K8S-0805-004 \
  --run-dir /var/tmp/saf-hardware/mig-test-1
```

Each phase appends a timestamp, source manifest and pseudonymous instance/boot
identifiers. Each case reads its expected receipt and records the file's
digest before completing. Provider preemption, lost transport, a missing
receipt or an incomplete stage leaves the live case open. Preserving a
completed threshold or admission checkpoint can narrow the remaining work
after a later cutoff. The allocator must report release before the full
catch-and-hold result passes. The optional `--port-base` changes the three
case-owned loopback ports if they are already in use.

Use the authorized cloud cleanup workflow for the exact rental and confirm
absence of its VM, boot disk, firewall, subnet and VPC in the provider account.
Keep the provider termination event with the run when the VM is preempted.
[K3s release pin](https://github.com/k3s-io/k3s/releases/tag/v1.36.6%2Bk3s1)
and [Google Cloud Spot VM lifecycle](https://docs.cloud.google.com/compute/docs/instances/spot).
