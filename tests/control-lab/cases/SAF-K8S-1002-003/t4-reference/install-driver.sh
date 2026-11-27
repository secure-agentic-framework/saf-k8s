#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
[[ $(uname -m) == x86_64 ]]
lspci -nn | grep -E 'Tesla T4.*\[10de:1eb8\]'
driver_version=580.178.04-0ubuntu0.22.04.1
kernel=$(uname -r)
module="linux-modules-nvidia-580-server-$kernel"
if ! apt-cache show "$module" >/dev/null 2>&1; then
    module="linux-headers-$kernel"
fi
printf 'Installing Jammy server GPU driver %s, guest kernel dependency %s\n' "$driver_version" "$module"
apt-get -o DPkg::Lock::Timeout=90 -qy install --no-install-recommends "$module" "nvidia-driver-580-server=$driver_version"
modprobe nvidia
modprobe nvidia_uvm
nvidia-smi --query-gpu=name,uuid,driver_version,compute_cap,pci.bus_id,memory.total --format=csv,noheader
