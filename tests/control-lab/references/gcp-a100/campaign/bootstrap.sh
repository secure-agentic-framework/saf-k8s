#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Bootstrap a dedicated A100 guest using the authoritative Secure Boot path.
# Keep Secure Boot enabled and use only Ubuntu signed kernel module packages.

readonly K3S_VERSION='v1.36.6+k3s1'
readonly NVIDIA_DRIVER_PACKAGE='nvidia-driver-580-server'
readonly NVIDIA_DRIVER_VERSION='580.178.04-0ubuntu0.22.04.1'
readonly NVIDIA_TOOLKIT_VERSION='1.20.2-1'
readonly DEVICE_PLUGIN_VERSION='v0.20.2'
workspace=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly BOOTSTRAP_ASSETS="$workspace/bootstrap-assets"
readonly STATE_DIR='/var/lib/saf-gpu-a100-bootstrap'
readonly K3S_CONFIG='/etc/rancher/k3s/config.yaml'

log() { printf '[saf-gpu-a100] %s\n' "$*"; }
die() { printf '[saf-gpu-a100] ERROR: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command missing: $1"; }

[[ $(id -u) -eq 0 ]] || die 'run as root, for example: sudo ./bootstrap.sh'
[[ -r /etc/os-release ]] || die 'cannot read /etc/os-release'
# shellcheck disable=SC1091
. /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 22.04 ]] || die "requires Ubuntu 22.04; found ${ID:-unknown} ${VERSION_ID:-unknown}"
[[ $(dpkg --print-architecture) == amd64 ]] || die 'requires amd64/x86_64'

[[ $(hostname) =~ ^saf-a100-[0-9]{10}$ ]] || die 'requires the disposable A100 validation host'

need apt-get
need dpkg-query
need python3
python3 -B "$workspace/bootstrap_assets.py" verify "$BOOTSTRAP_ASSETS"
mkdir -p "$STATE_DIR"

export DEBIAN_FRONTEND=noninteractive
keyring=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
if [[ -f "$keyring" ]]; then chmod 0644 "$keyring"; fi
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl gnupg lsb-release pciutils mokutil keyutils kmod psmisc
need lspci
need mokutil

mokutil --sb-state | grep -qi 'SecureBoot enabled' || die 'expected effective Secure Boot'
lspci -nn -d 10de: | grep -Eiq 'A100|GA100' || die 'no A100 device is visible'

kernel=$(uname -r)
signed_modules="linux-modules-nvidia-580-server-$kernel"
apt-cache show "$signed_modules" >/dev/null 2>&1 || die "Ubuntu signed package unavailable: $signed_modules"
if ! dpkg-query -W -f='${db:Status-Status}' "$signed_modules" 2>/dev/null | grep -Fxq installed; then
  apt-cache madison "$NVIDIA_DRIVER_PACKAGE" | awk '{print $3}' | grep -Fxq "$NVIDIA_DRIVER_VERSION" \
    || die "pinned Ubuntu driver $NVIDIA_DRIVER_VERSION is absent from configured Jammy repositories"
  log "installing signed modules for $kernel"
  apt-get install -y --no-install-recommends "$signed_modules" "$NVIDIA_DRIVER_PACKAGE=$NVIDIA_DRIVER_VERSION"
fi
module_path=$(modinfo -F filename nvidia)
[[ $module_path == "/lib/modules/$kernel/kernel/nvidia-580srv/nvidia.ko" ]]
signer=$(modinfo -F signer nvidia)
[[ $signer == 'Canonical Ltd. Kernel Module Signing' ]] || die 'unexpected NVIDIA module signer'
key_id=$(modinfo -F sig_key nvidia)
[[ $key_id == 'E9:DF:13:0F:92:92:A9:B7' ]] || die 'unexpected Ubuntu NVIDIA signing key'
for package in "$signed_modules" "linux-objects-nvidia-580-server-$kernel" "linux-signatures-nvidia-$kernel"; do
  dpkg-query -W -f='${db:Status-Status}' "$package" | grep -Fxq installed
  dpkg-query -W "$package"
done
lock=$(cat /sys/kernel/security/lockdown)
[[ $lock == *'[integrity]'* || $lock == *'[confidentiality]'* ]] || die 'kernel lockdown not active'
printf 'Canonical module %s, signer %s, key %s\n' "$module_path" "$signer" "$key_id"
modprobe nvidia
modprobe nvidia_uvm
gpu_lines=$(nvidia-smi --query-gpu=name --format=csv,noheader | sed '/^[[:space:]]*$/d')
[[ $(printf '%s\n' "$gpu_lines" | wc -l | tr -d ' ') == 1 ]] || die 'expected exactly one visible GPU'
[[ $gpu_lines == *A100* ]] || die "expected NVIDIA A100, found: $gpu_lines"
log "loaded Ubuntu signed driver, signer $signer"
driver=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader)
[[ $driver == '580.178.04' ]] || die 'running NVIDIA driver does not match the fixture pin'
log "verified GPU: $gpu_lines; driver $driver"

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

# The pinned binary, installer, and plugin manifest were materialized and
# verified in the workstation bundle. Set up K3s only after the NVIDIA
# runtime exists so it can discover that handler on first start.
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
if systemctl is-active --quiet k3s; then
  python3 -B "$workspace/bootstrap_assets.py" prepare-k3s "$BOOTSTRAP_ASSETS" --active
else
  python3 -B "$workspace/bootstrap_assets.py" prepare-k3s "$BOOTSTRAP_ASSETS"
  INSTALL_K3S_VERSION="$K3S_VERSION" INSTALL_K3S_SKIP_DOWNLOAD=true INSTALL_K3S_BIN_DIR=/usr/local/bin \
    INSTALL_K3S_EXEC='server' sh "$BOOTSTRAP_ASSETS/install-k3s.sh"
fi
systemctl enable --now k3s
for _ in $(seq 1 90); do
  if /usr/local/bin/k3s kubectl get --raw=/readyz >/dev/null 2>&1; then break; fi
  sleep 2
done
/usr/local/bin/k3s kubectl get --raw=/readyz >/dev/null 2>&1 || die 'K3s API did not become ready within 180 seconds'
[[ $(/usr/local/bin/k3s --version | awk 'NR == 1 {print $3}') == "$K3S_VERSION" ]] \
  || die 'installed K3s version does not match the pin'
api_version=$(/usr/local/bin/k3s kubectl get --raw=/version | python3 -c 'import json,sys; print(json.load(sys.stdin)["gitVersion"])')
[[ $api_version == "$K3S_VERSION" ]] || die 'running K3s API version does not match the pin'
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
plugin_manifest="$BOOTSTRAP_ASSETS/nvidia-device-plugin.yaml"
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
GPU=A100, observed through nvidia-smi on the signed driver
NVIDIA_DRIVER=${NVIDIA_DRIVER_PACKAGE}=${NVIDIA_DRIVER_VERSION}
NVIDIA_CONTAINER_TOOLKIT=1.20.2-1
K3S=${K3S_VERSION}
NVIDIA_DEVICE_PLUGIN=${DEVICE_PLUGIN_VERSION}
KUBERNETES_RUNTIME_CLASS=nvidia (legacy NVIDIA runtime injection; CDI not selected)
EOF
chmod 0600 "$STATE_DIR/pins.txt"
log 'bootstrap complete; one A100 is advertised as nvidia.com/gpu: 1'
log "pin record: $STATE_DIR/pins.txt"
log 'GPU workload Pods must set runtimeClassName: nvidia and request nvidia.com/gpu: 1.'
