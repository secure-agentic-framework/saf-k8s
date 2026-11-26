#!/bin/sh
set -eu
umask 077
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
original=/fixture/marker.o
awk '/^CapEff:/ {print "SAF-WORKLOAD-CAPABILITIES: " $2}' /proc/self/status
printf 'SAF-WORKLOAD-UID: %s\n' "$(id -u)"
base64 -d /trust/marker.sig.b64 >marker.sig
approved_digest=$(cat /trust/approved.sha256)
case "$approved_digest" in
    *[!0-9a-f]*|'') echo 'invalid fixture digest syntax' >&2; exit 1 ;;
esac
test "${#approved_digest}" -eq 64
openssl dgst -sha256 -verify /trust/anchor.pem -signature marker.sig "$original" >/dev/null
observed_digest=$(sha256sum "$original" | cut -d' ' -f1)
test "$observed_digest" = "$approved_digest"
echo approved_object_signature_verified
cp "$original" changed.o
printf '%s\n' 'Public fixture integrity comparison' >>changed.o
if openssl dgst -sha256 -verify /trust/anchor.pem -signature marker.sig changed.o >/dev/null 2>&1; then
    echo 'The changed object unexpectedly matched the approved signature' >&2
    exit 1
fi
echo modified_object_rejected_before_load
openssl dgst -sha256 -verify /trust/anchor.pem -signature marker.sig "$original" >/dev/null
echo approved_object_verifies

kernel=$(find /boot -maxdepth 1 -name 'vmlinuz-*' -print)
version=${kernel##*/vmlinuz-}
grep -qx 'CONFIG_BPF_SYSCALL=y' "/boot/config-$version"
if gzip -t "$kernel" >/dev/null 2>&1; then gzip -dc "$kernel" >kernel.img; else cp "$kernel" kernel.img; fi
mkdir -p fs/bin fs/dev fs/proc fs/sys
cp "$(command -v busybox)" fs/bin/busybox
tool=$(command -v bpftool)
cp "$tool" fs/bin/bpftool
ldd "$tool" | awk '$1 ~ /^\// {print $1} $2=="=>" && $3 ~ /^\// {print $3}' >libraries
while IFS= read -r library; do
    mkdir -p "$(dirname "fs$library")"
    cp -L "$library" "fs$library"
done <libraries
cp "$original" fs/marker.o
cmp "$original" fs/marker.o
printf '%s  /marker.o\n' "$approved_digest" >fs/marker.sha256
printf 'SAF-APPROVED-DIGEST: %s\n' "$approved_digest"
printf 'SAF-ALTERED-DIGEST: %s\n' "$(sha256sum changed.o | cut -d' ' -f1)"
printf 'SAF-APPROVED-TRUST-ANCHOR: %s\n' "$(sha256sum /trust/anchor.pem | cut -d' ' -f1)"
cat >fs/init <<'INIT'
#!/bin/busybox sh
set -eu
b=/bin/busybox
$b mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
trap '$b poweroff -f' EXIT
$b mount -t proc proc /proc
$b mount -t sysfs sysfs /sys
$b mount -t bpf bpf /sys/fs/bpf
test ! -e /sys/fs/bpf/saf_marker
$b sha256sum -c /marker.sha256
printf 'SAF-GUEST-DIGEST: %s\n' "$($b cut -d' ' -f1 /marker.sha256)"
printf 'SAF-GUEST-KERNEL: %s\n' "$($b uname -r)"
printf 'SAF-UNPRIVILEGED-BPF: %s\n' "$($b cat /proc/sys/kernel/unprivileged_bpf_disabled)"
printf 'SAF-GUEST-LOADER-UID: %s\n' "$($b id -u)"
printf 'SAF-BPF-BEFORE: %s\n' "$(/bin/bpftool -j prog show)"
/bin/bpftool prog load /marker.o /sys/fs/bpf/saf_marker
echo 'SAF-BPF-LOAD: succeeded'
printf 'SAF-BPF-LOADED: %s\n' "$(/bin/bpftool -j prog show pinned /sys/fs/bpf/saf_marker)"
printf 'SAF-BPF-ACTIVE: %s\n' "$(/bin/bpftool -j prog show)"
$b rm /sys/fs/bpf/saf_marker
test ! -e /sys/fs/bpf/saf_marker
for attempt in 1 2 3 4 5 6 7 8; do
    inventory=$(/bin/bpftool -j prog show)
    case "$inventory" in *'"name":"saf_marker"'*) $b sleep 1 ;; *) break ;; esac
done
printf 'SAF-BPF-AFTER: %s\n' "$inventory"
echo 'SAF-BPF-CLEANUP: pin removed'
$b poweroff -f
INIT
chmod 0755 fs/init
(cd fs && find . -print0 | cpio --null -o --owner=0:0 -H newc 2>/dev/null | gzip -n) >fixture.cpio.gz
if ! timeout 48s qemu-system-aarch64 -machine virt -accel tcg -cpu cortex-a57 -m 256M \
      -nodefaults -display none -serial stdio -monitor none -nic none \
      -kernel kernel.img -initrd fixture.cpio.gz \
      -append 'console=ttyAMA0 rdinit=/init panic=-1 loglevel=4' >guest.log 2>&1; then
    tail -32 guest.log >&2
    exit 1
fi
for expected in 'SAF-BPF-LOAD: succeeded' '"type":"socket_filter"' '"name":"saf_marker"' 'SAF-BPF-CLEANUP: pin removed'; do
    grep -Fq "$expected" guest.log || { tail -32 guest.log >&2; exit 1; }
done
tr -d '\r' <guest.log | grep '^SAF-'
echo approved_program_loaded_and_observed
