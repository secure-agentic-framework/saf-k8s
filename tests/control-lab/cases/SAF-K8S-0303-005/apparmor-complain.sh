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
grep -qx 'CONFIG_SECCOMP=y' "/boot/config-$version"
grep -qx 'CONFIG_SECCOMP_FILTER=y' "/boot/config-$version"
grep -qx 'CONFIG_AUDIT=y' "/boot/config-$version"
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
cp "$(command -v seccomp-proof)" fs/bin/seccomp-proof
cp /usr/local/share/saf/seccomp-proof.c fs/fixture/seccomp-proof.c
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
printf '0\n' >/proc/sys/kernel/printk_ratelimit
$b mount -t sysfs sysfs /sys
$b mount -t securityfs securityfs /sys/kernel/security
$b grep -qw log /proc/sys/kernel/seccomp/actions_avail
actions=$($b cat /proc/sys/kernel/seccomp/actions_logged)
case " $actions " in *' log '*) ;; *) echo "$actions log" > /proc/sys/kernel/seccomp/actions_logged ;; esac
$b grep -qw log /proc/sys/kernel/seccomp/actions_logged
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
/bin/busybox sha256sum /fixture/seccomp-proof.c | while read checksum file; do
    echo 'SAF-SC-FILTER-SHA256:' "$checksum"
done
observed=$(/bin/seccomp-proof observe)
echo "$observed"
observe_pid=$(echo "$observed" | $b sed -n 's/^SAF-SC-TASK: mode=observe pid=\([0-9][0-9]*\) syscall=getpid$/\1/p')
test -n "$observe_pid"
seccomp_event() {
    "$b" dmesg | "$b" grep 'type=1326' | "$b" grep "pid=$observe_pid " \
        | "$b" grep 'arch=c00000b7 syscall=172 ' | "$b" grep 'code=0x7ffc0000$'
}
event=''
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    event=$(seccomp_event || :)
    if test -n "$event"; then break; fi
    "$b" sleep .2
done
test -n "$event"
printf 'SAF-SC-AUDIT-EVENT: %s\n' "$event"
enforced=$(/bin/seccomp-proof enforce)
echo "$enforced"
/bin/seccomp-proof recover
$b poweroff -f
INIT
chmod 0755 fs/init
(cd fs && find . -print0 | cpio --null -o --owner=0:0 -H newc 2>/dev/null | gzip -n) >fixture.cpio.gz
if ! timeout 44s qemu-system-aarch64 -machine virt -accel tcg -cpu cortex-a57 -m 256M \
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
    'SAF-AA-AUDIT: removing the fixture policy restores both controls' \
    'SAF-SC-OBSERVE: getpid returned successfully under LOG action' \
    'SAF-SC-ENFORCE: getpid denied with EPERM; ordinary output succeeded' \
    'SAF-SC-RECOVERY: fresh unrestricted process completed getpid and output'; do
    grep -Fq "$expected" guest.log || { tail -50 guest.log >&2; exit 1; }
    printf '%s\n' "$expected"
done
grep -m 1 '^SAF-AA-AUDIT-EXPLICIT:' guest.log | tr -d '\r'
tr -d '\r' <guest.log | grep -E '^SAF-SC-(FILTER-SHA256|TASK|AUDIT-EVENT|ORDINARY):'
