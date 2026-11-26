#!/bin/bash
# Scratch publication launcher for SAF-K8S-0303-007 v10 guest proof.
set -Eeuo pipefail
umask 077

fail() { printf 'BLOCKED: %s\n' "$*" >&2; exit 2; }
[[ $# == 2 ]] || fail 'usage: publish-native-apparmor.sh EVIDENCE_DIRECTORY PINNED_K3S_ARM64_BINARY'
DEST=$1
K3S_BIN=$2
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd -P)
SCRIPT="$SCRIPT_DIR/run-native-apparmor-k3s.sh"
VM_CONFIG="$SCRIPT_DIR/test-vm.yaml"
EXPECTED_SCRIPT_SHA=71bfd23ba15274c5ba86280bd79337ee86e9c0c90db35a8392479b13d30c658f
EXPECTED_CONFIG_SHA=7069d871394496a49ce511fc81dba76c70909e4c4bdee06376819b9ec7088d00
EXPECTED_K3S_SHA=49dcecdb4f64f5e92bdc52d204d407fb39729e492f09074488125ee58b6f2895

command -v limactl >/dev/null || fail 'Lima is required'
command -v shasum >/dev/null || fail 'shasum is required'
command -v python3 >/dev/null || fail 'python3 is required for receipt validation'
[[ $(uname -m) == arm64 ]] || fail 'this tested guest candidate is scoped to Apple Silicon ARM64'
[[ -f "$SCRIPT" && $(shasum -a 256 "$SCRIPT" | awk '{print $1}') == "$EXPECTED_SCRIPT_SHA" ]] \
  || fail 'guest script differs from the exact tested v10 bytes'
[[ -f "$VM_CONFIG" && $(shasum -a 256 "$VM_CONFIG" | awk '{print $1}') == "$EXPECTED_CONFIG_SHA" ]] \
  || fail 'adjacent Lima VM config differs from the reviewed immutable config'
[[ -f "$K3S_BIN" && $(shasum -a 256 "$K3S_BIN" | awk '{print $1}') == "$EXPECTED_K3S_SHA" ]] \
  || fail 'supplied K3s binary is not the exact pinned ARM64 asset'
mkdir -p -- "$DEST"
DEST=$(cd -- "$DEST" && pwd -P)

stamp=$(date -u +%Y%m%dT%H%M%SZ)
nonce=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
instance="saf-k8s-0303-007-${stamp}-${nonce}"
if limactl list -q | grep -Fxq -- "$instance"; then fail 'generated Lima instance name is already in use'; fi
work=$(mktemp -d "${TMPDIR:-/tmp}/saf-0303-007-publish.XXXXXXXX")
chmod 700 "$work"
remote_dir=/var/tmp/saf-aa-case
created=false
published=false
cleanup_vm() {
  local status=0
  if $created && limactl list -q | grep -Fxq -- "$instance"; then
    limactl stop "$instance" >/dev/null 2>&1 || status=1
    limactl delete --force "$instance" >/dev/null 2>&1 || status=1
    if limactl list -q | grep -Fxq -- "$instance"; then status=1; fi
  fi
  created=false
  return "$status"
}
cleanup() {
  local rc=$?
  trap - EXIT INT TERM HUP
  if ! cleanup_vm; then
    printf 'BLOCKED: owned Lima guest cleanup could not be verified\n' >&2
    rc=1
  fi
  rm -rf -- "$work"
  if (( rc != 0 )) && ! $published; then
    printf 'No receipt was published. Inspect the disposable VM state before retrying.\n' >&2
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# --plain and --mount-none plus the copied config's mounts: [] prohibit host shares.
created=true  # Unique name was checked absent immediately before this owned start.
limactl start --name="$instance" --plain --mount-none --tty=false "$VM_CONFIG" \
  >"$work/lima-start.log" 2>&1 || fail 'Lima guest failed to start; logs are temporary and will be removed'
limactl shell --workdir /var/tmp "$instance" -- install -d -m 0700 /var/tmp/saf-aa-case \
  >"$work/guest-setup.log" 2>&1 || fail 'could not create private guest staging directory'
limactl copy "$K3S_BIN" "$instance:$remote_dir/k3s-arm64" \
  >"$work/copy-binary.log" 2>&1 || fail 'could not stage pinned K3s binary'
limactl copy "$SCRIPT" "$instance:$remote_dir/run-native-apparmor-k3s.sh" \
  >"$work/copy-script.log" 2>&1 || fail 'could not stage exact tested guest script'
limactl shell --workdir "$remote_dir" "$instance" -- chmod 0700 k3s-arm64 run-native-apparmor-k3s.sh \
  >"$work/guest-mode.log" 2>&1 || fail 'could not set private guest file modes'

run_rc=0
limactl shell --workdir "$remote_dir" "$instance" -- sudo env \
  SAF_K8S_0303_007_NATIVE_GUEST=I_OWN_THIS_DISPOSABLE_VM \
  SAF_K3S_BINARY="$remote_dir/k3s-arm64" /bin/bash ./run-native-apparmor-k3s.sh \
  >"$work/guest-run.log" 2>&1 || run_rc=$?
(( run_rc == 0 )) || fail 'guest proof did not exit successfully; no result will be published'
limactl shell "$instance" -- sudo /bin/bash -c \
  'set -e; cd /var/tmp/saf-aa-case; shopt -s nullglob; files=(SAF-K8S-0303-007-native-*.json); [ "${#files[@]}" -eq 1 ]; cat -- "${files[0]}"' \
  >"$work/result.json" 2>"$work/result-read.log" || fail 'could not retrieve the guest JSON receipt'

cleanup_vm || fail 'could not stop and delete the owned guest'

python3 - "$work/result.json" "$EXPECTED_SCRIPT_SHA" "$EXPECTED_K3S_SHA" <<'PY'
import json,sys
path,script_sha,k3s_sha=sys.argv[1:]
obj=json.load(open(path,encoding='utf-8'))
required={"api_ready":True,
 "baseline_allowed_and_denied_marker_reads":True,
 "profiled_allowed_read_denied_read_and_enforce_identity":True,
 "owned_k3s_and_namespace_cleanup_complete":True,
 "k3s_arm64_sha256":k3s_sha,
 "candidate_script_sha256":script_sha,
 "kubernetes_server_version":"v1.36.6+k3s1",
 "kubelet_version":"v1.36.6+k3s1"}
if any(obj.get(k)!=v for k,v in required.items()):
 raise SystemExit("receipt did not satisfy the exact positive evidence schema")
for key in ("namespace","profile_name","profile_sha256","guest_kernel_release","active_lsm_list"):
 if not isinstance(obj.get(key),str) or not obj[key]:
  raise SystemExit("receipt is missing a required sanitized identity field")
for value in ("fixed harmless allowed marker","fixed harmless denied marker","Bearer ","-----BEGIN"):
 if value in open(path,encoding='utf-8').read():
  raise SystemExit("receipt contains a prohibited marker or credential-like value")
PY

final="$DEST/SAF-K8S-0303-007-native-${instance}.json"
# Hard-link publication is atomic and refuses to replace a previous result.
ln "$work/result.json" "$final" || fail 'result destination already exists; previous evidence was preserved'
published=true
printf 'Published sanitized receipt: %s\n' "$final"
