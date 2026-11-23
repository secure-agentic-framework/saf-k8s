#!/bin/sh
set -eu
umask 077
profile=$(readlink -f "$1")
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
cp "$profile" fs/fixture/profile
for marker in allowed implicit explicit; do printf 'owned %s fixture\n' "$marker" >"fs/fixture/$marker"; done
digest=$(sha256sum "$profile" | awk '{print $1}')
cat >fs/init <<'INIT'
#!/bin/busybox sh
set -eu
b=/bin/busybox
$b mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
trap '$b dmesg | $b grep -F saf_complain_boundary | $b tail -16; $b poweroff -f' EXIT
$b mount -t proc proc /proc
$b mount -t sysfs sysfs /sys
$b mount -t securityfs securityfs /sys/kernel/security
profiles=/sys/kernel/security/apparmor/profiles
named=saf_complain_boundary
test "$($b cat /sys/module/apparmor/parameters/enabled)" = Y
test "$($b cat /fixture/implicit)" = 'owned implicit fixture'
test "$($b cat /fixture/explicit)" = 'owned explicit fixture'
echo 'SAF-AA-AUDIT: both owned comparison reads are initially available'
/bin/apparmor_parser -r -C -T /fixture/profile
$b grep -Fq "$named (complain)" "$profiles"
echo 'SAF-AA-AUDIT-INPUT:' "$($b sha256sum /fixture/profile)"
test "$(/bin/aa-exec -p "$named" -- $b cat /fixture/allowed)" = 'owned allowed fixture'
test "$(/bin/aa-exec -p "$named" -- $b cat /fixture/implicit)" = 'owned implicit fixture'
if /bin/aa-exec -p "$named" -- $b cat /fixture/explicit >/dev/null 2>&1; then
    echo 'SAF-AA-AUDIT-EXPLICIT: allowed by the pinned complain profile'
else
    echo 'SAF-AA-AUDIT-EXPLICIT: denied by the pinned complain profile'
fi
has_audit() {
    $b dmesg | $b grep 'apparmor="'$1'"' | $b grep 'profile="'$named'"' | $b grep -Fq 'name="/fixture/'$2'"'
}
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if has_audit ALLOWED implicit; then break; fi
    $b sleep .2
done
has_audit ALLOWED implicit
echo 'SAF-AA-AUDIT: complain allows the implicit would-be denial and records the expected event'
/bin/apparmor_parser -r -T /fixture/profile
$b grep -Fq "$named (enforce)" "$profiles"
test "$(/bin/aa-exec -p "$named" -- $b cat /fixture/allowed)" = 'owned allowed fixture'
if /bin/aa-exec -p "$named" -- $b cat /fixture/implicit 2>/dev/null; then exit 1; fi
if /bin/aa-exec -p "$named" -- $b cat /fixture/explicit 2>/dev/null; then exit 1; fi
echo 'SAF-AA-AUDIT: enforcing denies both while the approved read continues'
/bin/apparmor_parser -R /fixture/profile
test "$($b cat /fixture/implicit)" = 'owned implicit fixture'
test "$($b cat /fixture/explicit)" = 'owned explicit fixture'
echo 'SAF-AA-AUDIT: removing the fixture policy restores both controls'
$b poweroff -f
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
for expected in "SAF-AA-AUDIT-INPUT: $digest" \
    'SAF-AA-AUDIT: both owned comparison reads are initially available' \
    'SAF-AA-AUDIT: complain allows the implicit would-be denial and records the expected event' \
    'SAF-AA-AUDIT: enforcing denies both while the approved read continues' \
    'SAF-AA-AUDIT: removing the fixture policy restores both controls'; do
    grep -Fq "$expected" guest.log || { tail -50 guest.log >&2; exit 1; }
    printf '%s\n' "$expected"
done
grep -m 1 '^SAF-AA-AUDIT-EXPLICIT:' guest.log | tr -d '\r'
