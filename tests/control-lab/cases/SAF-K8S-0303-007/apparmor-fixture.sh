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
printf '%s\n' 'owned approved marker' >fs/fixture/allowed
printf '%s\n' 'owned denied marker' >fs/fixture/denied
digest=$(sha256sum "$profile" | awk '{print $1}')
cat >fs/init <<'INIT'
#!/bin/busybox sh
set -eu
b=/bin/busybox
$b mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
trap '$b poweroff -f' EXIT
$b mount -t proc proc /proc
$b mount -t sysfs sysfs /sys
$b mount -t securityfs securityfs /sys/kernel/security
profiles=/sys/kernel/security/apparmor/profiles
test "$($b cat /sys/module/apparmor/parameters/enabled)" = Y
test -r "$profiles"
if $b grep -q '^saf_read_boundary ' "$profiles"; then exit 1; fi
if /bin/aa-exec -p saf_read_boundary -- /bin/busybox cat /fixture/allowed >/dev/null 2>&1; then exit 1; fi
test "$($b cat /fixture/denied)" = 'owned denied marker'
echo 'SAF-AA: missing profile refused and unrestricted comparison read available'
/bin/apparmor_parser -r -T -W /fixture/profile
$b grep -Fq 'saf_read_boundary (enforce)' "$profiles"
echo 'SAF-AA: exact profile loaded in enforce mode'
echo 'SAF-AA-INPUT:' "$($b sha256sum /fixture/profile)"
/bin/aa-exec -p saf_read_boundary -- /bin/busybox sh -ec '
    test "$(/bin/busybox cat /fixture/allowed)" = "owned approved marker"
    /bin/busybox grep -Fq "saf_read_boundary (enforce)" /proc/self/attr/current
    if /bin/busybox cat /fixture/denied 2>/dev/null; then exit 1; fi
    echo "SAF-AA: expected read allowed and second read denied"
'
/bin/apparmor_parser -R /fixture/profile
if $b grep -q '^saf_read_boundary ' "$profiles"; then exit 1; fi
test "$($b cat /fixture/denied)" = 'owned denied marker'
echo 'SAF-AA: profile removed and comparison restored'
$b poweroff -f
INIT
chmod 0755 fs/init
(cd fs && find . -print0 | cpio --null -o --owner=0:0 -H newc 2>/dev/null | gzip -n) >fixture.cpio.gz
if ! timeout 34s qemu-system-aarch64 -machine virt -accel tcg -cpu cortex-a57 -m 256M \
      -nodefaults -display none -serial stdio -monitor none -nic none \
      -kernel kernel.img -initrd fixture.cpio.gz \
      -append 'console=ttyAMA0 rdinit=/init panic=-1 loglevel=4 apparmor=1 lsm=apparmor' >guest.log 2>&1; then
    tail -31 guest.log >&2
    exit 1
fi
for expected in 'SAF-AA: missing profile refused and unrestricted comparison read available' \
    'SAF-AA: exact profile loaded in enforce mode' "SAF-AA-INPUT: $digest" \
    'SAF-AA: expected read allowed and second read denied' 'SAF-AA: profile removed and comparison restored'; do
    grep -Fq "$expected" guest.log || { tail -35 guest.log >&2; exit 1; }
    printf '%s\n' "$expected"
done
