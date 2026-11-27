#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Single-node, single-tenant GCE T4 bootstrap for a fresh Ubuntu 22.04 amd64 VM.
# Run as root (or via sudo). A first run installs the driver and stops; reboot,
# then rerun to configure the NVIDIA runtime, install pinned K3s, and deploy the
# pinned NVIDIA device plugin. This script does not create or contact a GCE VM.

readonly K3S_VERSION='v1.36.6+k3s1'
readonly K3S_INSTALLER_URL='https://raw.githubusercontent.com/k3s-io/k3s/v1.36.6%2Bk3s1/install.sh'
readonly NVIDIA_DRIVER_PACKAGE='nvidia-driver-580-server'
readonly NVIDIA_DRIVER_VERSION='580.178.04-0ubuntu0.22.04.1'
readonly NVIDIA_TOOLKIT_VERSION='1.20.2-1'
readonly DEVICE_PLUGIN_VERSION='v0.20.2'
readonly DEVICE_PLUGIN_MANIFEST_URL='https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/v0.20.2/deployments/static/nvidia-device-plugin.yml'
readonly STATE_DIR='/var/lib/saf-gpu-t4-bootstrap'
readonly K3S_CONFIG='/etc/rancher/k3s/config.yaml'

log() { printf '[saf-gpu-t4] %s\n' "$*"; }
die() { printf '[saf-gpu-t4] ERROR: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command missing: $1"; }

[[ $(id -u) -eq 0 ]] || die 'run as root, for example: sudo ./bootstrap-t4-k3s.sh'
[[ -r /etc/os-release ]] || die 'cannot read /etc/os-release'
# shellcheck disable=SC1091
. /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 22.04 ]] || die "requires Ubuntu 22.04; found ${ID:-unknown} ${VERSION_ID:-unknown}"
[[ $(dpkg --print-architecture) == amd64 ]] || die 'requires amd64/x86_64'

need apt-get
need dpkg-query
mkdir -p "$STATE_DIR"

export DEBIAN_FRONTEND=noninteractive
keyring=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
if [[ -f "$keyring" ]]; then chmod 0644 "$keyring"; fi
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl gnupg lsb-release pciutils mokutil dkms build-essential "linux-headers-$(uname -r)"
need lspci
need mokutil

if mokutil --sb-state 2>/dev/null | grep -qi 'SecureBoot enabled'; then
  die 'Secure Boot is enabled. This path uses Ubuntu DKMS modules without MOK enrollment; provision the VM with Secure Boot disabled or use an approved signed-driver procedure.'
fi

# GCE T4 PCI vendor/device is 10de:1eb8. Check presence before installing a
# kernel module; after reboot, nvidia-smi must identify exactly one Tesla T4.
lspci -nn -d 10de: | grep -qi '1eb8' || die 'no NVIDIA T4 PCI device (10de:1eb8) is visible; check GCE GPU attachment and VM type'

installed_driver=$(dpkg-query -W -f='${Version}' "$NVIDIA_DRIVER_PACKAGE" 2>/dev/null || true)
if [[ $installed_driver != "$NVIDIA_DRIVER_VERSION" ]]; then
  apt-cache madison "$NVIDIA_DRIVER_PACKAGE" | awk '{print $3}' | grep -Fxq "$NVIDIA_DRIVER_VERSION" || die "pinned Ubuntu driver $NVIDIA_DRIVER_VERSION is absent from configured Jammy repositories"
  log "installing $NVIDIA_DRIVER_PACKAGE=$NVIDIA_DRIVER_VERSION; a reboot is required before continuing"
  apt-get install -y --no-install-recommends "$NVIDIA_DRIVER_PACKAGE=$NVIDIA_DRIVER_VERSION"
  apt-mark hold "$NVIDIA_DRIVER_PACKAGE" >/dev/null
  printf '%s\n' "$NVIDIA_DRIVER_VERSION" > "$STATE_DIR/driver-version"
  log 'driver installation finished. Reboot the VM, then rerun this script.'
  exit 0
fi
apt-mark hold "$NVIDIA_DRIVER_PACKAGE" >/dev/null

if ! command -v nvidia-smi >/dev/null 2>&1 || ! nvidia-smi -L >/dev/null 2>&1; then
  die 'NVIDIA driver is installed but not active. Reboot the VM, then rerun this script.'
fi
gpu_lines=$(nvidia-smi --query-gpu=name --format=csv,noheader | sed '/^[[:space:]]*$/d')
[[ $(printf '%s\n' "$gpu_lines" | wc -l | tr -d ' ') == 1 ]] || die 'expected exactly one visible GPU'
[[ $gpu_lines == 'Tesla T4' ]] || die "expected Tesla T4, found: $gpu_lines"
log "verified GPU: $gpu_lines; driver $(nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -n1 | xargs)"

# NVIDIA's signed APT repository and exact component versions. Do not configure
# host /etc/containerd: K3s embeds containerd and detects runtime binaries when
# its service starts. CDI is intentionally not selected for this test.
install -d -m 0755 /usr/share/keyrings
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
  | gpg --dearmor --yes -o "$keyring"
chmod 0644 "$keyring"
curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
  | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
  > /etc/apt/sources.list.d/nvidia-container-toolkit.list
apt-get update
apt-get install -y --no-install-recommends \
  "nvidia-container-toolkit=$NVIDIA_TOOLKIT_VERSION" \
  "nvidia-container-toolkit-base=$NVIDIA_TOOLKIT_VERSION" \
  "libnvidia-container-tools=$NVIDIA_TOOLKIT_VERSION" \
  "libnvidia-container1=$NVIDIA_TOOLKIT_VERSION"
apt-mark hold nvidia-container-toolkit nvidia-container-toolkit-base libnvidia-container-tools libnvidia-container1 >/dev/null
for package in nvidia-container-toolkit nvidia-container-toolkit-base libnvidia-container-tools libnvidia-container1; do
  version=$(dpkg-query -W -f='${Version}' "$package")
  [[ $version == "$NVIDIA_TOOLKIT_VERSION" ]] || die "$package version mismatch: $version"
done
command -v nvidia-container-runtime >/dev/null || die 'toolkit did not install nvidia-container-runtime in PATH'

# The versioned K3s installer downloads the exact release and verifies the
# release-provided SHA256 before installing. Installing it only after the
# runtime executable exists lets K3s discover the NVIDIA handler at first boot.
installer="$STATE_DIR/install-k3s-${K3S_VERSION}.sh"
if [[ ! -s $installer ]]; then
  curl -fsSLo "$installer" "$K3S_INSTALLER_URL"
  chmod 0700 "$installer"
fi
grep -q 'INSTALL_K3S_VERSION' "$installer" || die 'downloaded K3s installer did not pass the versioned-source sanity check'
install -d -m 0755 /etc/rancher/k3s
if [[ ! -e $K3S_CONFIG ]]; then
  cat > "$K3S_CONFIG" <<'EOF'
write-kubeconfig-mode: "0600"
disable:
  - traefik
  - servicelb
EOF
  chmod 0600 "$K3S_CONFIG"
fi
if ! systemctl is-active --quiet k3s; then
  INSTALL_K3S_VERSION="$K3S_VERSION" INSTALL_K3S_EXEC='server' sh "$installer"
fi
systemctl enable --now k3s
for _ in $(seq 1 90); do
  if /usr/local/bin/k3s kubectl get --raw=/readyz >/dev/null 2>&1; then break; fi
  sleep 2
done
/usr/local/bin/k3s kubectl get --raw=/readyz >/dev/null 2>&1 || die 'K3s API did not become ready within 180 seconds'
/usr/local/bin/k3s --version | grep -Fq "$K3S_VERSION" || die 'running K3s version does not match the pin'
runtime_config='/var/lib/rancher/k3s/agent/etc/containerd/config.toml'
[[ -s $runtime_config ]] || die "K3s containerd config is missing: $runtime_config"
grep -q 'nvidia' "$runtime_config" || die 'K3s containerd did not discover the NVIDIA runtime; inspect K3s PATH and restart only after diagnosis'
for _ in $(seq 1 45); do
  if /usr/local/bin/k3s kubectl get runtimeclass nvidia >/dev/null 2>&1; then break; fi
  sleep 2
done
[[ $(/usr/local/bin/k3s kubectl get runtimeclass nvidia -o jsonpath='{.handler}') == nvidia ]] || die 'K3s did not publish the NVIDIA RuntimeClass'

# Install NVIDIA's official pinned static device-plugin manifest. The plugin
# needs RuntimeClass nvidia on K3s; add that field to the one exact upstream
# DaemonSet after validating the pinned image line. No workload is launched.
plugin_manifest="$STATE_DIR/nvidia-device-plugin-${DEVICE_PLUGIN_VERSION}.yaml"
if [[ ! -s $plugin_manifest ]]; then
  curl -fsSLo "$plugin_manifest" "$DEVICE_PLUGIN_MANIFEST_URL"
fi
grep -Fxq "      - image: nvcr.io/nvidia/k8s-device-plugin:${DEVICE_PLUGIN_VERSION}" "$plugin_manifest" || die 'device-plugin manifest image does not match the pinned release'
python3 - "$plugin_manifest" "$STATE_DIR/nvidia-device-plugin-runtimeclass.yaml" <<'PY'
from pathlib import Path
import sys
src, dst = map(Path, sys.argv[1:])
text = src.read_text()
needle = '      priorityClassName: "system-node-critical"\n'
if text.count(needle) != 1:
    raise SystemExit('pinned upstream manifest shape changed; refusing to patch')
if '      runtimeClassName: nvidia\n' in text:
    raise SystemExit('unexpected existing runtimeClassName in upstream source')
dst.write_text(text.replace(needle, needle + '      runtimeClassName: nvidia\n'))
PY
/usr/local/bin/k3s kubectl apply -f "$STATE_DIR/nvidia-device-plugin-runtimeclass.yaml"
/usr/local/bin/k3s kubectl -n kube-system rollout status daemonset/nvidia-device-plugin-daemonset --timeout=180s

node_count=$(/usr/local/bin/k3s kubectl get nodes -o jsonpath='{.items[*].metadata.name}' | awk '{print NF}')
[[ $node_count == 1 ]] || die "expected exactly one K3s node, found $node_count"
node=$(/usr/local/bin/k3s kubectl get nodes -o jsonpath='{.items[0].metadata.name}')
for _ in $(seq 1 30); do
  gpu_count=$(/usr/local/bin/k3s kubectl get node "$node" -o jsonpath='{.status.allocatable.nvidia\.com/gpu}')
  if [[ "$gpu_count" == 1 ]]; then break; fi
  sleep 2
done
[[ $gpu_count == 1 ]] || die "device plugin has not advertised exactly one nvidia.com/gpu (got '${gpu_count:-missing}')"
plugin_runtime=$(/usr/local/bin/k3s kubectl -n kube-system get daemonset nvidia-device-plugin-daemonset -o jsonpath='{.spec.template.spec.runtimeClassName}')
[[ $plugin_runtime == nvidia ]] || die "device plugin is not configured for RuntimeClass nvidia (got '${plugin_runtime:-missing}')"

cat > "$STATE_DIR/pins.txt" <<EOF
OS=Ubuntu ${VERSION_ID} amd64
GPU=Tesla T4; PCI 10de:1eb8; compute capability 7.5 (NVIDIA published table)
NVIDIA_DRIVER=${NVIDIA_DRIVER_PACKAGE}=${NVIDIA_DRIVER_VERSION}
NVIDIA_CONTAINER_TOOLKIT=1.20.2-1
K3S=${K3S_VERSION}
NVIDIA_DEVICE_PLUGIN=${DEVICE_PLUGIN_VERSION}
KUBERNETES_RUNTIME_CLASS=nvidia (legacy NVIDIA runtime injection; CDI not selected)
EOF
chmod 0600 "$STATE_DIR/pins.txt"
log 'bootstrap complete; one T4 is advertised as nvidia.com/gpu: 1'
log "pin record: $STATE_DIR/pins.txt"
log 'GPU workload Pods must set runtimeClassName: nvidia and request nvidia.com/gpu: 1.'
