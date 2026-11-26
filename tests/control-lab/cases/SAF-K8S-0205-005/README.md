# Verify admission restrictions and the lifecycle of a signed inert marker

    python3 tests/control-lab/lab.py test SAF-K8S-0205-005 --docker-context desktop-linux

The case compares ordinary and init-container capability requests before and
after restricted admission. An unprivileged disposable Job reports its
non-root UID and zero effective capabilities.

The runner generates a temporary key outside Kubernetes, signs the exact
fixed object from the locally built fixture image, and removes the private
key before creating the Job. A read-only ConfigMap supplies the public
key, detached signature and approved digest. The Job accepts the approved
bytes and rejects a changed copy before booting the guest. The isolated guest
rechecks the digest, observes one unattached program's inventory ID and tag,
then removes that pin and confirms the inventory entry disappears.

The guest uses the pinned Debian ARM64 Linux 6.12.118 and QEMU image build.
The runner requires a local openssl executable with EC signing support.

For a deployment, inventory the actual kernel, loader, provider components
and capabilities. Verify build provenance, approved digest and enrolled trust
source, kernel authorization and applicable signed-program policy. Reconcile
attributable load decisions, attach and detach events and continuing inventory.
Set collection and retention requirements for the adopted versions and review
kernel, trust, sensor or attachment changes. The portable case's program
stays unattached inside the emulated guest.
