#!/usr/bin/env bash
# Run only in your dedicated disposable Linux VM.
set -Eeuo pipefail
umask 077
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
test "${SAF_K8S_0701_003_DISPOSABLE_GUEST:-}" = I_OWN_THIS_DISPOSABLE_VM || die 'dedicated guest opt-in required'
test "$(id -u)" = 0 || die 'root required inside the disposable guest'
systemd-detect-virt --vm >/dev/null || die 'a virtual machine is required'
test -z "$(findmnt -rn -t virtiofs,9p || true)" || die 'the VM must have no mounted host shares'
for cmd in cryptsetup losetup truncate mkfs.ext4 mount umount findmnt grep cmp openssl sync kind kubectl python3; do
  command -v "$cmd" >/dev/null || die "required guest command missing: $cmd"
done

work=$(mktemp -d /var/tmp/saf-k8s-0701-003.XXXXXXXX)
disk="$work/container.luks"
plain="$work/reference.ext4"
mountpoint="$work/mount"
mapper="saf-crypt-$(openssl rand -hex 6)"
key="$work/guest-only.key"
wrong="$work/wrong.key"
marker_a='SAF synthetic local alpha after ordinary update'
marker_b='SAF synthetic local beta marker'
marker_pod='SAF synthetic Kubernetes PV marker on encrypted backing'
loop=''
mapped=0
mounted=0
clean() {
  local status=$?
  trap - EXIT INT TERM HUP
  if (( mounted )); then umount "$mountpoint" || status=1; fi
  if (( mapped )); then cryptsetup close "$mapper" || status=1; fi
  if [[ -n "$loop" ]]; then losetup -d "$loop" || status=1; fi
  if ! findmnt --mountpoint "$mountpoint" >/dev/null; then
    [[ "$work" =~ ^/var/tmp/saf-k8s-0701-003\.[A-Za-z0-9]+$ ]] && rm -rf -- "$work"
  fi
  [[ ! -e "$work" ]] || status=1
  if (( status == 0 )); then printf 'GUEST_FIXTURE_CLEANUP=true\n'; fi
  exit "$status"
}
trap clean EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
install -d -m700 "$mountpoint"

# Plain ext4 establishes that the exact marker probe can see an ordinary backed write.
truncate -s 64M "$plain"
mkfs.ext4 -q -F "$plain"
mount -o loop "$plain" "$mountpoint"
mounted=1
printf '%s\n' "$marker_pod" > "$mountpoint/reference.txt"
sync
umount "$mountpoint"
mounted=0
grep -aFq -- "$marker_pod" "$plain" || die 'plaintext control marker was not found'
printf 'PLAIN_REFERENCE_MARKER_VISIBLE=true\n'

truncate -s 512M "$disk"
openssl rand -out "$key" 64
printf '%s\n' 'different synthetic key fixture' > "$wrong"
loop=$(losetup --find --show "$disk")
cryptsetup luksFormat --type luks2 --batch-mode --key-file "$key" --label saf-k8s-0701-003 "$loop"
cryptsetup open --key-file "$key" "$loop" "$mapper"
mapped=1
mkfs.ext4 -q -F "/dev/mapper/$mapper"
mount "/dev/mapper/$mapper" "$mountpoint"
mounted=1
printf '%s\n' 'SAF synthetic local alpha before ordinary update' > "$mountpoint/alpha"
printf '%s\n' "$marker_b" > "$mountpoint/beta"
test "$(cat "$mountpoint/alpha")" = 'SAF synthetic local alpha before ordinary update'
printf '%s\n' "$marker_a" > "$mountpoint/alpha"
test "$(cat "$mountpoint/alpha")" = "$marker_a"
test "$(cat "$mountpoint/beta")" = "$marker_b"
printf 'ORDINARY_LOCAL_FILE_READ_WRITE=true\n'
bash "$(dirname "$0")/guest-pv-probe.sh" "$work" "$mountpoint"

sync
for marker in "$marker_a" "$marker_b" "$marker_pod"; do
  status=0
  grep -aFq -- "$marker" "$disk" || status=$?
  test "$status" = 1 || die 'encrypted backing contained the marker or could not be read'
done
printf 'EXACT_MARKERS_ABSENT_FROM_ENCRYPTED_BACKING=true\n'
cryptsetup luksDump "$loop" | awk '/^Version:/ {print "LUKS_HEADER_VERSION=" $2; exit}'
umount "$mountpoint"
mounted=0
cryptsetup close "$mapper"
mapped=0
result=0
cryptsetup open --test-passphrase --key-file "$wrong" "$loop" > "$work/wrong-key.log" 2>&1 || result=$?
test "$result" = 2 && grep -qi 'No key available' "$work/wrong-key.log"
printf 'WRONG_KEY_REJECTED=true\n'
cryptsetup open --key-file "$key" "$loop" "$mapper"
mapped=1
mount "/dev/mapper/$mapper" "$mountpoint"
mounted=1
test "$(cat "$mountpoint/alpha")" = "$marker_a"
test "$(cat "$mountpoint/beta")" = "$marker_b"
relative=$(cat "$work/pv-relative-path")
[[ "$relative" =~ ^provisioner/pvc-[0-9a-f-]+_saf-encrypted-volume_fixture-storage/pod-marker\.txt$ ]]
test "$(cat "$mountpoint/$relative")" = "$marker_pod"
printf 'ALL_SYNTHETIC_FILES_REOPENED=true\n'
