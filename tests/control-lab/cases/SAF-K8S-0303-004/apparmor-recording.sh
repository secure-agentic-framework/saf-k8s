#!/bin/sh
set -eu
umask 077
recorder=$(readlink -f "$1")
approval=$(readlink -f "$2")
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
cp "$recorder" fs/fixture/recorder
cp "$approval" fs/fixture/approved
for marker in startup recovery incidental; do printf 'owned %s fixture\n' "$marker" >"fs/fixture/$marker"; done
digest1=$(sha256sum "$recorder" | awk '{print $1}')
digest2=$(sha256sum "$approval" | awk '{print $1}')
cat >fs/init <<'INIT'
#!/bin/busybox sh
set -eu
b=/bin/busybox
$b mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
trap '$b dmesg | $b grep -F saf_record_boundary | $b tail -12; $b poweroff -f' EXIT
$b mount -t proc proc /proc
# The disconnected boot fixture uses the kernel console audit fallback.
# Ensure one synthetic event cannot suppress the next by printk rate limiting.
printf '0\n' >/proc/sys/kernel/printk_ratelimit
$b mount -t sysfs sysfs /sys
$b mount -t securityfs securityfs /sys/kernel/security
named=saf_record_boundary
profiles=/sys/kernel/security/apparmor/profiles
test "$($b cat /sys/module/apparmor/parameters/enabled)" = Y
probe() { /bin/aa-exec -p "$named" -- "$b" cat "/fixture/$1"; }
events() {
    "$b" dmesg | "$b" grep -F 'apparmor="ALLOWED"' | "$b" grep -F 'profile="saf_record_boundary"' |
      "$b" sed -n 's/.*operation="open".* name="\(\/fixture\/[a-z][a-z]*\)".*/\1/p' | "$b" sort -u
}
wait_for_event() {
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        if events | "$b" grep -Fxq "/fixture/$1"; then return 0; fi
        "$b" sleep .2
    done
    return 1
}
derive() {
    events >/tmp/observed-paths
    # Fixed fixture-only grammar and exact approval intersection. No general
    # filesystem glob, regex generation, network rule, or automatic promotion.
    "$b" sed '$d' /fixture/recorder
    while IFS= read -r path; do
        if "$b" grep -Fxq "$path" /fixture/approved; then printf '    %s r,\n' "$path"; fi
    done </tmp/observed-paths
    printf '}\n'
}
echo "SAF-RECORD-INPUT: $($b sha256sum /fixture/recorder | $b cut -d' ' -f1) $($b sha256sum /fixture/approved | $b cut -d' ' -f1)"
/bin/apparmor_parser -r -C -T /fixture/recorder
"$b" grep -Fq "$named (complain)" "$profiles"
test "$(probe startup)" = 'owned startup fixture'
test "$(probe incidental)" = 'owned incidental fixture'
wait_for_event startup
wait_for_event incidental
derive >/tmp/limited.apparmor
"$b" grep -Fq '/fixture/startup r,' /tmp/limited.apparmor
if "$b" grep -Eq '/fixture/(recovery|incidental) r,' /tmp/limited.apparmor; then exit 1; fi
/bin/apparmor_parser -r -T /tmp/limited.apparmor
"$b" grep -Fq "$named (enforce)" "$profiles"
test "$(probe startup)" = 'owned startup fixture'
if probe recovery >/dev/null 2>&1; then exit 1; fi
echo 'SAF-RECORD: first capture observes incidental use and misses a required recovery operation'
/bin/apparmor_parser -r -C -T /fixture/recorder
"$b" grep -Fq "$named (complain)" "$profiles"
test "$(probe recovery)" = 'owned recovery fixture'
wait_for_event recovery
derive >/tmp/reviewed.apparmor
"$b" grep -Fq '/fixture/recovery r,' /tmp/reviewed.apparmor
if "$b" grep -Fq '/fixture/incidental r,' /tmp/reviewed.apparmor; then exit 1; fi
echo "SAF-RECORD-PROFILES: $($b sha256sum /tmp/limited.apparmor | $b cut -d' ' -f1) $($b sha256sum /tmp/reviewed.apparmor | $b cut -d' ' -f1)"
/bin/apparmor_parser -r -T /tmp/reviewed.apparmor
"$b" grep -Fq "$named (enforce)" "$profiles"
test "$(probe startup)" = 'owned startup fixture'
test "$(probe recovery)" = 'owned recovery fixture'
if probe incidental >/dev/null 2>&1; then exit 1; fi
echo 'SAF-RECORD: the reviewed generated policy preserves approved operations and excludes the observed incidental one'
/bin/apparmor_parser -R /tmp/reviewed.apparmor
if probe startup >/dev/null 2>&1; then exit 1; fi
echo 'SAF-RECORD: the generated fixture policy is removed'
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
for expected in "SAF-RECORD-INPUT: $digest1 $digest2" \
    'SAF-RECORD: first capture observes incidental use and misses a required recovery operation' \
    'SAF-RECORD: the reviewed generated policy preserves approved operations and excludes the observed incidental one' \
    'SAF-RECORD: the generated fixture policy is removed'; do
    grep -Fq "$expected" guest.log || { tail -48 guest.log >&2; exit 1; }
    printf '%s\n' "$expected"
done
grep -m 1 '^SAF-RECORD-PROFILES:' guest.log | tr -d '\r'
