#!/bin/sh
set -eu
umask 077
test "$#" -eq 2
test "$1" != "$2"
for level in "$@"; do printf '%s\n' "$level" | grep -Ex 's0:c[0-9]+,c[0-9]+' > /dev/null; done
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

kernel=$(find /boot -maxdepth 1 -name 'vmlinuz-*' -print)
version=${kernel##*/vmlinuz-}
grep -qx 'CONFIG_SECURITY_SELINUX=y' "/boot/config-$version"
if gzip -t "$kernel" >/dev/null 2>&1; then gzip -dc "$kernel" >kernel.img; else cp "$kernel" kernel.img; fi
mkdir -p fs/bin fs/dev fs/etc/selinux fs/fixture fs/proc fs/sys fs/tmp
cp /usr/bin/busybox fs/bin/busybox
for executable in /usr/sbin/load_policy /usr/sbin/setenforce /usr/bin/chcon /usr/bin/runcon /usr/bin/id; do
    cp "$executable" "fs/bin/${executable##*/}"
    ldd "$executable" | awk '$1 ~ /^\// {print $1} $2=="=>" && $3 ~ /^\// {print $3}' >libraries
    while IFS= read -r library; do
        mkdir -p "$(dirname "fs$library")"
        cp -L "$library" "fs$library"
    done <libraries
done
policy=$(find /etc/selinux/default/policy -name 'policy.*' -type f)
mkdir -p fs/etc/selinux/default/policy
cp "$policy" fs/etc/selinux/default/policy/
cp /etc/selinux/config fs/etc/selinux/config
digest=$(sha256sum "$policy" | awk '{print $1}')
printf '%s\n' 'owned canary a' >fs/fixture/a
printf '%s\n' 'owned canary b' >fs/fixture/b
chmod 0644 fs/fixture/a fs/fixture/b
printf '%s\n' "a_level=$1" "b_level=$2" >fs/fixture/levels
for marker in go switch result-a result-b; do : >"fs/fixture/$marker"; done
cat >fs/fixture/worker <<'WORKER'
expected=$1
own=$2
other=$3
result=$4
read -r ctx < /proc/self/attr/current || :
test "$ctx" = "$expected" || exit 10
printf '%s\n' ready >"$result"
while ! read -r stage < /fixture/go || [ "$stage" != active ]; do /bin/busybox sleep .1; done
if ! read -r data <"/fixture/$own" || [ "$data" != "owned canary $own" ]; then exit 11; fi
if ( read -r data <"/fixture/$other" ) 2>/dev/null; then exit 12; fi
printf '%s\n' boundary-observed >"$result"
while ! read -r stage < /fixture/switch || [ "$stage" != active ]; do /bin/busybox sleep .1; done
if [ "$own" = a ]; then
    if ! read -r data </fixture/b || [ "$data" != "owned canary b" ]; then exit 13; fi
else
    if ( read -r data </fixture/b ) 2>/dev/null; then exit 14; fi
fi
printf '%s\n' relabel-observed >"$result"
WORKER
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
$b mount -t selinuxfs selinuxfs /sys/fs/selinux
$b grep -wq selinux /sys/kernel/security/lsm
/bin/load_policy -i
. /fixture/levels
echo 'SAF-SELINUX-POLICY:' "$($b sha256sum /etc/selinux/default/policy/policy.*)"
/bin/chcon system_u:object_r:container_file_t:s0 /bin/busybox /fixture /fixture/worker /fixture/go /fixture/switch
/bin/chcon "system_u:object_r:container_file_t:$a_level" /fixture/a /fixture/result-a
/bin/chcon "system_u:object_r:container_file_t:$b_level" /fixture/b /fixture/result-b
test "$($b stat -c '%u:%g:%a' /fixture/a)" = "$($b stat -c '%u:%g:%a' /fixture/b)"
a="system_u:system_r:container_t:$a_level"
b_label="system_u:system_r:container_t:$b_level"
/bin/setenforce 0
test "$($b cat /sys/fs/selinux/enforce)" = 0
test "$(/bin/runcon "$a" /bin/busybox cat /fixture/b)" = 'owned canary b'

wait_for_both() {
    for attempt in $($b seq 1 50); do
        if $b grep -qx "$1" /fixture/result-a && $b grep -qx "$1" /fixture/result-b; then return 0; fi
        $b sleep .1
    done
    echo "expected $1 in both processes"
    $b cat /fixture/result-a /fixture/result-b
    $b dmesg | $b grep 'avc:' | $b tail -25
    return 1
}

# Start both owned processes during setup and keep their exact contexts
# unchanged for all enforcing comparisons and the object relabel.
/bin/runcon "$a" /bin/busybox sh /fixture/worker "$a" a b /fixture/result-a >/dev/null 2>&1 &
pa=$!
/bin/runcon "$b_label" /bin/busybox sh /fixture/worker "$b_label" b a /fixture/result-b >/dev/null 2>&1 &
pb=$!
wait_for_both ready
/bin/setenforce 1
test "$($b cat /sys/fs/selinux/enforce)" = 1
echo 'SAF-SELINUX: matched DAC comparison and enforcing'
printf '%s\n' active >/fixture/go
wait_for_both boundary-observed
echo 'SAF-SELINUX: both category boundaries enforced with process category observations'
echo "SAF-SELINUX-CONTEXTS: $a $b_label"
/bin/chcon "system_u:object_r:container_file_t:$a_level" /fixture/b
printf '%s\n' active >/fixture/switch
wait_for_both relabel-observed
wait "$pa"
wait "$pb"
echo 'SAF-SELINUX: changing only object categories changes both decisions'
$b poweroff -f
INIT
chmod 0755 fs/init
(cd fs && find . -print0 | cpio --null -o --owner=0:0 -H newc 2>/dev/null | gzip -n) >fixture.cpio.gz
if ! timeout 42s qemu-system-aarch64 -machine virt -accel tcg -cpu cortex-a57 -m 320M \
      -nodefaults -display none -serial stdio -monitor none -nic none \
      -kernel kernel.img -initrd fixture.cpio.gz \
      -append 'console=ttyAMA0 rdinit=/init panic=-1 loglevel=4 audit=1 enforcing=0 lsm=selinux' >guest.log 2>&1; then
    tail -42 guest.log >&2
    exit 1
fi
for expected in "SAF-SELINUX-POLICY: $digest" \
    "SAF-SELINUX-CONTEXTS: system_u:system_r:container_t:$1 system_u:system_r:container_t:$2" 'SAF-SELINUX: matched DAC comparison and enforcing' \
    'SAF-SELINUX: both category boundaries enforced with process category observations' \
    'SAF-SELINUX: changing only object categories changes both decisions'; do
    grep -Fq "$expected" guest.log || { tail -52 guest.log >&2; exit 1; }
    printf '%s\n' "$expected"
done
