#!/bin/bash
# Run only inside the case-owned, mount-free Debian VM.
set -euo pipefail
sudo apt-get update -q
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    podman uidmap slirp4netns fuse-overlayfs curl
if ! id safroot >/dev/null 2>&1; then
    sudo useradd --create-home --shell /bin/bash safroot
fi
sudo loginctl enable-linger safroot
grep '^safroot:' /etc/subuid /etc/subgid
fixture_uid=$(id -u safroot)
for attempt in {1..30}; do
    if sudo -u safroot test -S "/run/user/$fixture_uid/bus"; then
        exit 0
    fi
    sleep 1
done
exit 1
