#!/bin/sh
set -eu
umask 077
original=$(readlink -f "$1")
revision=$(readlink -f "$2")
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
for marker in normal recovery excluded; do printf 'owned %s fixture\n' "$marker" >"fs/fixture/$marker"; done
digest1=$(sha256sum "$original" | awk '{print $1}')
digest2=$(sha256sum "$revision" | awk '{print $1}')
test "$digest1" != "$digest2"
cat >fs/init <<'INIT'
#!/bin/busybox sh
set -eu
b=/bin/busybox
$b mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
trap '$b dmesg | $b grep -F saf_refinement_boundary | $b tail -10; $b poweroff -f' EXIT
$b mount -t proc proc /proc
# The disconnected boot fixture uses the kernel console audit fallback.
# Ensure one synthetic event cannot suppress the next by printk rate limiting.
printf '0\n' >/proc/sys/kernel/printk_ratelimit
$b mount -t sysfs sysfs /sys
$b mount -t securityfs securityfs /sys/kernel/security
profiles=/sys/kernel/security/apparmor/profiles
named=saf_refinement_boundary
test "$($b cat /sys/module/apparmor/parameters/enabled)" = Y
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
echo "SAF-REFINE-INPUT: $($b sha256sum /fixture/original | $b cut -d' ' -f1) $($b sha256sum /fixture/revision | $b cut -d' ' -f1)"
/bin/apparmor_parser -r -C -T /fixture/original
"$b" grep -Fq "$named (complain)" "$profiles"
test "$(probe normal)" = 'owned normal fixture'
test "$(probe normal)" = 'owned normal fixture'
# An excluded canary first proves the audit channel functions for this profile.
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
/bin/apparmor_parser -r -T /fixture/revision
"$b" grep -Fq "$named (enforce)" "$profiles"
test "$(probe normal)" = 'owned normal fixture'
test "$(probe recovery)" = 'owned recovery fixture'
if probe excluded >/dev/null 2>&1; then exit 1; fi
echo 'SAF-REFINE: the exact revision keeps the approved paths and still denies the excluded path'
/bin/apparmor_parser -R /fixture/revision
if probe normal >/dev/null 2>&1; then exit 1; fi
echo 'SAF-REFINE: loaded revision removed'
"$b" poweroff -f
INIT
chmod 0755 fs/init
(cd fs && find . -print0 | cpio --null -o --owner=0:0 -H newc 2>/dev/null | gzip -n) >fixture.cpio.gz
if ! timeout 34s qemu-system-aarch64 -machine virt -accel tcg -cpu cortex-a57 -m 256M \
      -nodefaults -display none -serial stdio -monitor none -nic none \
      -kernel kernel.img -initrd fixture.cpio.gz \
      -append 'console=ttyAMA0 rdinit=/init panic=-1 loglevel=5 audit=1 apparmor=1 lsm=apparmor' >guest.log 2>&1; then
    tail -31 guest.log >&2
    exit 1
fi
for expected in "SAF-REFINE-INPUT: $digest1 $digest2" \
    'SAF-REFINE: two ordinary cycles are clean despite coverage excluding recovery' \
    'SAF-REFINE: the original policy misses the recovery path and enforcing blocks it' \
    'SAF-REFINE: the exact revision keeps the approved paths and still denies the excluded path' \
    'SAF-REFINE: loaded revision removed'; do
    grep -Fq "$expected" guest.log || { tail -45 guest.log >&2; exit 1; }
    printf '%s\n' "$expected"
done
