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
ln -s busybox fs/bin/sh
tool=$(command -v bpftool)
cp "$tool" fs/bin/bpftool
chmod 0555 fs/bin/busybox fs/bin/bpftool
ldd "$tool" | awk '$1 ~ /^\// {print $1} $2=="=>" && $3 ~ /^\// {print $3}' >libraries
while IFS= read -r library; do
    mkdir -p "$(dirname "fs$library")"
    cp -L "$library" "fs$library"
    chmod 0555 "fs$library"
done <libraries
find fs -type d -exec chmod 0755 {} +
cp "$original" fs/marker.o
cmp "$original" fs/marker.o
chmod 0444 fs/marker.o
cp "$attachment" fs/attach_marker.o
cmp "$attachment" fs/attach_marker.o
printf '%s  /marker.o\n' "$approved_digest" >fs/marker.sha256
chmod 0444 fs/marker.o fs/marker.sha256
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
# Run exactly one failed load attempt as an unprivileged guest identity. The
# same signed marker already passed the root loader above; no sysctl is changed.
refused_parent=/sys/fs/bpf/saf-0205-005-unprivileged
approved_digest=$($b cut -d ' ' -f1 /marker.sha256)
if ! $b --list | $b grep -qx su; then
    printf 'SAF-BPF-REFUSED-LOAD: {"result":"blocked","reason":"pinned_busybox_su_applet_unavailable"}\n'
else
    $b mkdir -p /etc
    printf '%s\n' 'root:x:0:0:guest root:/:/bin/sh' 'saf-bpf-deny:x:65534:65534:case-only BPF denial user:/:/bin/sh' > /etc/passwd
    printf '%s\n' 'root:x:0:' 'saf-bpf-deny:x:65534:' > /etc/group
    if $b mkdir "$refused_parent" && $b chmod 0777 "$refused_parent"; then
      if $b su -s /bin/sh saf-bpf-deny -c '\
        test "$(/bin/busybox id -u)" = 65534 || exit 31; \
        test "$(/bin/busybox id -g)" = 65534 || exit 32; \
        echo exact_guest_uid_gid_verified; \
        cap_eff=$(/bin/busybox awk "/^CapEff:/ {print \$2}" /proc/self/status); \
        test "$cap_eff" = 0000000000000000 || exit 33; \
        echo zero_effective_capabilities_verified; \
        test "$(/bin/busybox cat /proc/sys/kernel/unprivileged_bpf_disabled)" = 2 || exit 34; \
        /bin/busybox sha256sum -c /marker.sha256 >/dev/null || exit 35; \
        echo identity_digest_and_zero_caps_verified; \
        /bin/busybox mkdir /sys/fs/bpf/saf-0205-005-unprivileged/preflight || exit 36; \
        /bin/busybox rmdir /sys/fs/bpf/saf-0205-005-unprivileged/preflight || exit 37; \
        echo writable_pin_parent_verified; \
        echo bpf_prog_load_attempted; \
        exec /bin/bpftool prog load /marker.o /sys/fs/bpf/saf-0205-005-unprivileged/refused' \
          >unprivileged-load.stdout 2>unprivileged-load.stderr; then
          load_status=0
      else
          load_status=$?
      fi
      pin_absent=false
      if test ! -e "$refused_parent/refused"; then pin_absent=true; fi
      identity_verified=false
      identity_and_digest=false
      cap_eff_zero=false
      pin_parent_verified=false
      load_attempted=false
      if $b grep -Fxq exact_guest_uid_gid_verified unprivileged-load.stdout; then identity_verified=true; fi
      if $b grep -Fxq zero_effective_capabilities_verified unprivileged-load.stdout; then cap_eff_zero=true; fi
      if $b grep -Fxq identity_digest_and_zero_caps_verified unprivileged-load.stdout; then identity_and_digest=true; fi
      if $b grep -Fxq writable_pin_parent_verified unprivileged-load.stdout; then pin_parent_verified=true; fi
      if $b grep -Fxq bpf_prog_load_attempted unprivileged-load.stdout; then load_attempted=true; fi
      load_eprem=false
      rejection_stage=unclassified
      if $b grep -Fq 'failed to load program: Operation not permitted' unprivileged-load.stderr \
         || $b grep -Fq 'BPF program load failed: Operation not permitted' unprivileged-load.stderr; then
          load_eprem=true
          rejection_stage=object_program_load
      elif $b grep -Eq 'bpf_object__probe_loading\(\):[[:space:]]*Operation not permitted\(1\).*trivial BPF' unprivileged-load.stderr; then
          # The pin's libbpf probe calls BPF_PROG_LOAD before loading the object.
          load_eprem=true
          rejection_stage=libbpf_prog_load_probe
      fi
      if test "$load_status" -eq 0; then
          # This path is uniquely case-owned; remove only an unexpected exact pin.
          $b rm -f "$refused_parent/refused"
          result=unexpected_success
      elif test "$identity_and_digest" != true || test "$pin_parent_verified" != true || test "$load_attempted" != true; then
          result=inconclusive_preflight
      elif test "$load_eprem" = true && test "$pin_absent" = true; then
          result=load_eprem
      else
          result=inconclusive_error_stage
      fi
      $b rmdir "$refused_parent"
      printf 'SAF-BPF-REFUSED-LOAD: {"result":"%s","uid":65534,"gid":65534,"identity_uid_gid_verified":%s,"cap_eff_zero":%s,"loader_exit_status":%s,"setting":"%s","approved_sha256":"%s","identity_and_digest_verified":%s,"writable_pin_parent_verified":%s,"load_attempted":%s,"load_stage_eprem":%s,"rejection_stage":"%s","pin_absent":%s}\n' \
          "$result" "$identity_verified" "$cap_eff_zero" "$load_status" "$($b cat /proc/sys/kernel/unprivileged_bpf_disabled)" \
          "$approved_digest" "$identity_and_digest" "$pin_parent_verified" "$load_attempted" "$load_eprem" "$rejection_stage" "$pin_absent"
    else
      printf 'SAF-BPF-REFUSED-LOAD: {"result":"blocked","reason":"case_owned_bpffs_pin_parent_unavailable"}\n'
    fi
fi
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
for expected in 'SAF-BPF-LOAD: succeeded' '"type":"socket_filter"' '"name":"saf_marker"' 'SAF-BPF-CLEANUP: pin removed' 'SAF-BPF-ATTACHMENT: ' 'SAF-BPF-REFUSED-LOAD: '; do
    grep -Fq "$expected" guest.log || { tail -32 guest.log >&2; exit 1; }
done
tr -d '\r' <guest.log | grep '^SAF-'
echo approved_program_loaded_and_observed
