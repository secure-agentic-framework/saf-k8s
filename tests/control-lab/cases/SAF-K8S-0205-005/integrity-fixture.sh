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
attachment=/fixture/attach_marker.o
base64 -d /trust/attach.sig.b64 >attach_marker.sig
attachment_digest=$(cat /trust/attach.sha256)
case "$attachment_digest" in
    *[!0-9a-f]*|'') echo 'invalid attachment digest syntax' >&2; exit 1 ;;
esac
test "${#attachment_digest}" -eq 64
openssl dgst -sha256 -verify /trust/anchor.pem -signature attach_marker.sig "$attachment" >/dev/null
observed_attachment_digest=$(sha256sum "$attachment" | cut -d' ' -f1)
test "$observed_attachment_digest" = "$attachment_digest"
echo approved_attachment_signature_verified

kernel=$(find /boot -maxdepth 1 -name 'vmlinuz-*' -print)
version=${kernel##*/vmlinuz-}
grep -qx 'CONFIG_BPF_SYSCALL=y' "/boot/config-$version"
grep -qx 'CONFIG_CGROUP_BPF=y' "/boot/config-$version"
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
cp "$attachment" fs/attach_marker.o
cmp "$attachment" fs/attach_marker.o
printf '%s  /marker.o\n' "$approved_digest" >fs/marker.sha256
printf '%s  /attach_marker.o\n' "$attachment_digest" >fs/attach_marker.sha256
printf 'SAF-APPROVED-DIGEST: %s\n' "$approved_digest"
printf 'SAF-ALTERED-DIGEST: %s\n' "$(sha256sum changed.o | cut -d' ' -f1)"
printf 'SAF-APPROVED-TRUST-ANCHOR: %s\n' "$(sha256sum /trust/anchor.pem | cut -d' ' -f1)"
printf 'SAF-ATTACH-APPROVED-DIGEST: %s\n' "$attachment_digest"
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
$b sha256sum -c /attach_marker.sha256
attachment_digest=$($b cut -d ' ' -f1 /attach_marker.sha256)
$b mount -t cgroup2 cgroup2 /sys/fs/cgroup
$b mkdir /sys/fs/cgroup/saf-0205-005
/bin/bpftool prog load /attach_marker.o /sys/fs/bpf/saf_sysctl \
    type cgroup/sysctl pinmaps /sys/fs/bpf/saf-attach-maps
attachment_type=$(/bin/bpftool -j prog show pinned /sys/fs/bpf/saf_sysctl)
printf '%s' "$attachment_type" | $b tr -d '[:space:]' | $b grep -Fq '"type":"cgroup_sysctl"'
printf 'SAF-BPF-ATTACH-PROGRAM: %s\n' "$attachment_type"
map_path=/sys/fs/bpf/saf-attach-maps/sysctl_hits
counter_value() {
    observed=$(/bin/bpftool -j map lookup pinned "$map_path" key hex 00 00 00 00)
    value=$(printf '%s' "$observed" | $b tr -d '[:space:]' \
        | $b sed -n 's/.*"formatted":{"key":0,"value":\([0-9][0-9]*\)}.*/\1/p')
    case "$value" in ''|*[!0-9]*) printf 'Fixture counter could not be decoded\n' >&2; return 1;; esac
    printf '%s\n' "$value"
}
count_before=$(counter_value)
test "$count_before" -eq 0
/bin/bpftool cgroup attach /sys/fs/cgroup/saf-0205-005 cgroup_sysctl \
    pinned /sys/fs/bpf/saf_sysctl
attached=$(/bin/bpftool cgroup show /sys/fs/cgroup/saf-0205-005)
printf '%s\n' "$attached" | $b grep -Fq 'sysctl'
printf '%s\n' "$attached" | $b grep -Fq 'saf_sysctl'
$b sh -c 'echo $$ > /sys/fs/cgroup/saf-0205-005/cgroup.procs; \
    /bin/busybox grep -Fq "0::/saf-0205-005" /proc/self/cgroup; \
    /bin/busybox cat /proc/sys/kernel/hostname >/dev/null'
count_attached=$(counter_value)
test "$count_attached" -gt 0
/bin/bpftool cgroup detach /sys/fs/cgroup/saf-0205-005 cgroup_sysctl \
    pinned /sys/fs/bpf/saf_sysctl
detached=$(/bin/bpftool cgroup show /sys/fs/cgroup/saf-0205-005)
if printf '%s\n' "$detached" | $b grep -Fq 'saf_sysctl'; then
    echo 'The case-owned BPF attachment remained after detach' >&2
    exit 1
fi
$b sh -c 'echo $$ > /sys/fs/cgroup/saf-0205-005/cgroup.procs; \
    /bin/busybox grep -Fq "0::/saf-0205-005" /proc/self/cgroup; \
    /bin/busybox cat /proc/sys/kernel/hostname >/dev/null'
count_detached=$(counter_value)
test "$count_detached" -eq "$count_attached"
$b rm /sys/fs/bpf/saf_sysctl
$b rm "$map_path"
$b rmdir /sys/fs/bpf/saf-attach-maps
$b rmdir /sys/fs/cgroup/saf-0205-005
$b umount /sys/fs/cgroup
printf 'SAF-BPF-ATTACHMENT: {"signature_verified":true,"approved_sha256":"%s","program_type":"cgroup_sysctl","cgroup_path":"/sys/fs/cgroup/saf-0205-005","attached_program_matches":true,"counter_before":%s,"counter_after_attached_read":%s,"detached_program_absent":true,"counter_after_detached_read":%s,"cgroup_removed":true}\n' \
    "$attachment_digest" "$count_before" "$count_attached" "$count_detached"
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
for expected in 'SAF-BPF-LOAD: succeeded' '"type":"socket_filter"' '"name":"saf_marker"' 'SAF-BPF-CLEANUP: pin removed' 'SAF-BPF-ATTACHMENT: '; do
    grep -Fq "$expected" guest.log || { tail -32 guest.log >&2; exit 1; }
done
tr -d '\r' <guest.log | grep '^SAF-'
echo approved_program_loaded_and_observed
