#!/bin/sh
set -eu
umask 077
original=$(readlink -f "$1")
revision=$(readlink -f "$2")
approved=$(readlink -f "$3")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
kernel=$(find /boot -maxdepth 1 -name 'vmlinuz-*' -print)
version=${kernel##*/vmlinuz-}
grep -qx 'CONFIG_SECURITY_APPARMOR=y' "/boot/config-$version"
if gzip -t "$kernel" >/dev/null 2>&1; then gzip -dc "$kernel" >kernel.img; else cp "$kernel" kernel.img; fi
mkdir -p fs/bin fs/dev fs/etc/apparmor.d fs/fixture fs/proc fs/sys fs/tmp
cp "$(command -v busybox)" fs/bin/busybox
for program in apparmor_parser aa-exec; do
    executable=$(command -v "$program")
    cp "$executable" "fs/bin/$program"
    ldd "$executable" | awk '$1 ~ /^\// {print $1} $2=="=>" && $3 ~ /^\// {print $3}' >libraries
    while IFS= read -r library; do
        mkdir -p "$(dirname "fs$library")"
        cp -L "$library" "fs$library"
    done <libraries
done
cp "$original" fs/fixture/original
cp "$revision" fs/fixture/revision
cp "$approved" fs/fixture/approved.sha256
for marker in normal recovery excluded; do printf 'owned %s fixture\n' "$marker" >"fs/fixture/$marker"; done
digest1=$(sha256sum "$original" | awk '{print $1}')
digest2=$(sha256sum "$revision" | awk '{print $1}')
test "$digest1" != "$digest2"
cat >fs/init <<'INIT'
#!/bin/busybox sh
set -eu
b=/bin/busybox
"$b" mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
trap '$b dmesg | $b grep -F saf_refinement_boundary | $b tail -16; $b poweroff -f' EXIT
"$b" mount -t proc proc /proc
printf '0\n' >/proc/sys/kernel/printk_ratelimit
"$b" mount -t sysfs sysfs /sys
"$b" mount -t securityfs securityfs /sys/kernel/security
profiles=/sys/kernel/security/apparmor/profiles
named=saf_refinement_boundary
test "$("$b" cat /sys/module/apparmor/parameters/enabled)" = Y
probe() { /bin/aa-exec -p "$named" -- "$b" cat "/fixture/$1"; }
has_audit() {
    "$b" dmesg | "$b" grep -F 'apparmor="ALLOWED"' | "$b" grep -F 'profile="saf_refinement_boundary"' | "$b" grep -Fq 'name="/fixture/'"$1"'"'
}
wait_for_audit() {
    for cycle in 1 2 3 4 5 6 7 8 9 10; do
        if has_audit "$1"; then return 0; fi
        "$b" sleep .2
    done
    return 1
}
file_hash() { "$b" sha256sum "$1" | "$b" cut -d' ' -f1; }
orig_hash=$(file_hash /fixture/original)
rev_hash=$(file_hash /fixture/revision)
echo "SAF-REFINE-INPUT: $orig_hash $rev_hash"
/bin/apparmor_parser -r -C -T /fixture/original
"$b" grep -Fq "$named (complain)" "$profiles"
test "$(probe normal)" = 'owned normal fixture'
test "$(probe normal)" = 'owned normal fixture'
test "$(probe excluded)" = 'owned excluded fixture'
wait_for_audit excluded
if has_audit normal; then exit 1; fi
echo 'SAF-REFINE: two ordinary cycles are clean despite coverage excluding recovery'
test "$(probe recovery)" = 'owned recovery fixture'
wait_for_audit recovery
/bin/apparmor_parser -r -T /fixture/original
"$b" grep -Fq "$named (enforce)" "$profiles"
if probe recovery >/dev/null 2>&1; then exit 1; fi
echo 'SAF-REFINE: the original policy misses the recovery path and enforcing blocks it'
approved_hash=$("$b" cat /fixture/approved.sha256)
test "$approved_hash" = "$rev_hash"
echo 'SAF-REFINE: specified recovery and excluded probe events calibrated against clean normal reads'
promote() {
    if test "$(file_hash "$1")" != "$approved_hash"; then return 27; fi
    /bin/apparmor_parser -r -T "$1"
}
"$b" cp /fixture/revision /tmp/changed.apparmor
printf '\n# synthetic unapproved edit\n' >>/tmp/changed.apparmor
code=0
promote /tmp/changed.apparmor || code=$?
test "$code" = 27
"$b" grep -Fq "$named (enforce)" "$profiles"
test "$(probe normal)" = 'owned normal fixture'
if probe recovery >/dev/null 2>&1; then exit 1; fi
echo 'SAF-REFINE: modified unapproved revision rejected; active profile unchanged'
promote /fixture/revision
"$b" grep -Fq "$named (enforce)" "$profiles"
test "$(probe normal)" = 'owned normal fixture'
test "$(probe recovery)" = 'owned recovery fixture'
if probe excluded >/dev/null 2>&1; then exit 1; fi
echo 'SAF-REFINE: approved exact revision promoted and allows normal and recovery while denying excluded'
# Roll back to exact prior bytes and verify different live outcomes.
/bin/apparmor_parser -r -T /fixture/original
test "$(file_hash /fixture/original)" = "$orig_hash"
"$b" grep -Fq "$named (enforce)" "$profiles"
test "$(probe normal)" = 'owned normal fixture'
if probe recovery >/dev/null 2>&1; then exit 1; fi
echo 'SAF-REFINE: rollback restored prior exact profile; normal allowed and recovery denied'
# A predictable new case-owned file read re-triggers observation, then enforcing denial.
printf 'owned changed fixture\n' >/fixture/workload-added-path
test "$("$b" cat /fixture/workload-added-path)" = 'owned changed fixture'
/bin/apparmor_parser -r -C -T /fixture/original
test "$(probe workload-added-path)" = 'owned changed fixture'
wait_for_audit workload-added-path
/bin/apparmor_parser -r -T /fixture/original
"$b" grep -Fq "$named (enforce)" "$profiles"
if probe workload-added-path >/dev/null 2>&1; then exit 1; fi
echo 'SAF-REFINE: synthetic workload change re-triggered; new path observed and enforcing profile denied it'
/bin/apparmor_parser -R /fixture/original
if probe normal >/dev/null 2>&1; then exit 1; fi
echo 'SAF-REFINE: fixture profile removed'
"$b" poweroff -f
INIT
chmod 0755 fs/init
(cd fs && find . -print0 | cpio --null -o --owner=0:0 -H newc 2>/dev/null | gzip -n) >fixture.cpio.gz
if ! timeout 46s qemu-system-aarch64 -machine virt -accel tcg -cpu cortex-a57 -m 256M \
      -nodefaults -display none -serial stdio -monitor none -nic none \
      -kernel kernel.img -initrd fixture.cpio.gz \
      -append 'console=ttyAMA0 rdinit=/init panic=-1 loglevel=5 audit=1 apparmor=1 lsm=apparmor' >guest.log 2>&1; then
    tail -35 guest.log >&2
    exit 1
fi
tr -d '\r' <guest.log >guest-lines.log
for expected in "SAF-REFINE-INPUT: $digest1 $digest2" \
    'SAF-REFINE: two ordinary cycles are clean despite coverage excluding recovery' \
    'SAF-REFINE: the original policy misses the recovery path and enforcing blocks it' \
    'SAF-REFINE: specified recovery and excluded probe events calibrated against clean normal reads' \
    'SAF-REFINE: modified unapproved revision rejected; active profile unchanged' \
    'SAF-REFINE: approved exact revision promoted and allows normal and recovery while denying excluded' \
    'SAF-REFINE: rollback restored prior exact profile; normal allowed and recovery denied' \
    'SAF-REFINE: synthetic workload change re-triggered; new path observed and enforcing profile denied it' \
    'SAF-REFINE: fixture profile removed'; do
    grep -Fxq "$expected" guest-lines.log || { tail -55 guest.log >&2; exit 1; }
    printf '%s\n' "$expected"
done
