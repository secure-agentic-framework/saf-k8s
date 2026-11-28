#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $(id -u) -eq 0 ]]
[[ $(hostname) =~ ^saf-a100-[0-9]{10}$ ]]
command -v fuser >/dev/null
profile=$(nvidia-smi --query-gpu=name,driver_version --format=csv,noheader)
[[ "$profile" == "NVIDIA A100-SXM4-40GB, 580.178.04" ]]
state=$(nvidia-smi --query-gpu=mig.mode.current,mig.mode.pending --format=csv,noheader)
case "$state" in
  'Enabled, Enabled')
    echo 'MIG_ACTIVE: preserve the existing layout and Device Plugin'
    exit 0
    ;;
  'Disabled, Enabled')
    echo 'MIG_PENDING: preserve the request and verify after the approved reboot'
    exit 4
    ;;
  'Disabled, Disabled') ;;
  *)
    echo 'MIG_UNCONFIRMED: review the current and pending mode'
    exit 3
    ;;
esac
k() { /usr/local/bin/k3s kubectl "$@"; }
[[ $(k get nodes -o jsonpath='{.items[0].metadata.name}') == "$(hostname)" ]]
k -n saf-gpu-a100 delete pod a100-vector-witness --ignore-not-found=true --wait=true --timeout=70s
k -n saf-gpu-observe delete daemonset dcgm-exporter --cascade=foreground --ignore-not-found=true --wait=true --timeout=70s
k -n kube-system delete daemonset nvidia-device-plugin-daemonset --cascade=foreground --ignore-not-found=true --wait=true --timeout=70s
systemctl stop nvidia-persistenced.service 2>/dev/null || true
compute_pids=$(nvidia-smi --query-compute-apps=pid --format=csv,noheader)
[[ -z "$compute_pids" ]] || { echo 'STOP: active compute application'; exit 3; }
devices=(/dev/nvidia0 /dev/nvidiactl)
[[ ! -c /dev/nvidia-uvm ]] || devices+=(/dev/nvidia-uvm)
set +e
fuser "${devices[@]}" >/dev/null 2>&1
handles=$?
set -e
[[ "$handles" -eq 1 ]] || { echo 'STOP: device still in use or GPU handle check failed'; exit 3; }
set +e
nvidia-smi -i 0 -mig 1
code=$?
set -e
state=$(nvidia-smi --query-gpu=mig.mode.current,mig.mode.pending --format=csv,noheader)
printf '%s\n' "$state"
case "$state" in
  'Enabled, Enabled')
    [[ "$code" -eq 0 ]]
    echo 'MIG_ACTIVE'
    ;;
  'Disabled, Enabled')
    echo 'MIG_PENDING: reboot the guest, then verify current mode'
    exit 4
    ;;
  *)
    echo 'MIG_UNCONFIRMED: current active profile was not established'
    exit 3
    ;;
esac
