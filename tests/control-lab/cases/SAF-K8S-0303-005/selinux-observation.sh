#!/bin/sh
set -eu
umask 077
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
printf '%s\n' 'ordinary marker' >fs/fixture/ordinary
printf '%s\n' 'comparison marker' >fs/fixture/comparison
chmod 0644 fs/fixture/ordinary fs/fixture/comparison
: >fs/fixture/stage
: >fs/fixture/reply
cat >fs/fixture/observe <<'OBSERVER'
set -eu
b=/bin/busybox
level=$1
IFS= read -r context </proc/self/attr/current || :
test "$context" = "$level"
printf 'ready %s %s\n' "$$" "$context" >/fixture/reply
for phase in permissive enforcing recovery; do
    while ! IFS= read -r stage </fixture/stage || test "$stage" != "$phase"; do "$b" sleep .1; done
    IFS= read -r context </proc/self/attr/current || :
    test "$context" = "$level"
    IFS= read -r ordinary </fixture/ordinary
    test "$ordinary" = 'ordinary marker'
    decision=denied
    if { IFS= read -r comparison </fixture/comparison && test "$comparison" = 'comparison marker'; }; then
        decision=allowed
    fi
    printf '%s %s %s\n' "$phase" "$decision" "$$" >/fixture/reply
done
OBSERVER
cat >fs/init <<'INIT'
#!/bin/busybox sh
set -eu
b=/bin/busybox
"$b" mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
trap '"$b" dmesg | "$b" grep -i "avc:" | "$b" tail -18; "$b" poweroff -f' EXIT
"$b" mount -t proc proc /proc
printf '0\n' >/proc/sys/kernel/printk_ratelimit
"$b" mount -t sysfs sysfs /sys
"$b" mount -t securityfs securityfs /sys/kernel/security
"$b" mount -t selinuxfs selinuxfs /sys/fs/selinux
"$b" grep -wq selinux /sys/kernel/security/lsm
/bin/load_policy -i
/bin/setenforce 0
test "$("$b" cat /sys/fs/selinux/enforce)" = 0

subject=system_u:system_r:container_t:s0:c10,c20
ordinary=system_u:object_r:container_file_t:s0:c10,c20
comparison=system_u:object_r:container_file_t:s0:c11,c21
/bin/chcon system_u:object_r:container_file_t:s0 /bin/busybox /fixture /fixture/observe /fixture/stage
/bin/chcon "$ordinary" /fixture/ordinary /fixture/reply
/bin/chcon "$comparison" /fixture/comparison
test "$("$b" stat -c '%u:%g:%a' /fixture/ordinary)" = "$("$b" stat -c '%u:%g:%a' /fixture/comparison)"
echo "SAF-SELINUX-OBSERVE-POLICY: $("$b" sha256sum /etc/selinux/default/policy/policy.* | "$b" cut -d' ' -f1)"
echo "SAF-SELINUX-OBSERVE-CONTEXTS: $subject $ordinary $comparison"

/bin/runcon "$subject" /bin/busybox sh /fixture/observe "$subject" &
worker=$!
wait_reply() {
    for loop in $("$b" seq 1 50); do
        if "$b" grep -Fxq "$*" /fixture/reply; then return; fi
        "$b" sleep .1
    done
    echo "SAF-SELINUX-OBSERVE-ERROR: probe did not report $*"
    "$b" cat /fixture/reply
    exit 1
}
wait_reply ready "$worker" "$subject"
avc() {
    "$b" dmesg | "$b" grep 'avc:.*denied.*{[^}]*read[^}]*}' |
        "$b" grep -F "pid=$worker " |
        "$b" grep -F 'name="comparison"' |
        "$b" grep -F "scontext=$subject " |
        "$b" grep -F "tcontext=$comparison " |
        "$b" grep -F "tclass=file permissive=$1"
}
require_avc() {
    for loop in $("$b" seq 1 20); do
        matched=$(avc "$1" || :)
        if test -n "$matched"; then
            printf 'SAF-SELINUX-OBSERVE-AVC-%s: %s\n' "$1" "$matched"
            return
        fi
        "$b" sleep .1
    done
    echo "SAF-SELINUX-OBSERVE-ERROR: missing correlated AVC for mode $1"
    exit 1
}

printf '%s\n' permissive >/fixture/stage
wait_reply permissive allowed "$worker"
require_avc 1
echo 'SAF-SELINUX-OBSERVE: permissive allowed both reads and recorded the would-deny AVC'

/bin/setenforce 1
test "$("$b" cat /sys/fs/selinux/enforce)" = 1
printf '%s\n' enforcing >/fixture/stage
wait_reply enforcing denied "$worker"
require_avc 0
echo 'SAF-SELINUX-OBSERVE: enforcing allowed the ordinary read and denied the same comparison read'

/bin/setenforce 0
test "$("$b" cat /sys/fs/selinux/enforce)" = 0
printf '%s\n' recovery >/fixture/stage
wait_reply recovery allowed "$worker"
wait "$worker"
/bin/setenforce 1
test "$("$b" cat /sys/fs/selinux/enforce)" = 1
echo 'SAF-SELINUX-OBSERVE: the observation rollback restored the read and the guest finished enforcing'
"$b" poweroff -f
INIT
chmod 0755 fs/init
(cd fs && find . -print0 | cpio --null -o --owner=0:0 -H newc 2>/dev/null | gzip -n) >fixture.cpio.gz
if ! timeout 55s qemu-system-aarch64 -machine virt -accel tcg -cpu cortex-a57 -m 320M \
      -nodefaults -display none -serial stdio -monitor none -nic none \
      -kernel kernel.img -initrd fixture.cpio.gz \
      -append 'console=ttyAMA0 rdinit=/init panic=-1 loglevel=5 audit=1 enforcing=0 lsm=selinux' >guest.log 2>&1; then
    tail -65 guest.log >&2
    exit 1
fi
tr -d '\r' <guest.log >guest-lines.log
for expected in "SAF-SELINUX-OBSERVE-POLICY: $digest" \
    'SAF-SELINUX-OBSERVE: permissive allowed both reads and recorded the would-deny AVC' \
    'SAF-SELINUX-OBSERVE: enforcing allowed the ordinary read and denied the same comparison read' \
    'SAF-SELINUX-OBSERVE: the observation rollback restored the read and the guest finished enforcing'; do
    grep -Fxq "$expected" guest-lines.log || { tail -75 guest.log >&2; exit 1; }
done
grep -E '^SAF-SELINUX-OBSERVE(:|-POLICY:|-CONTEXTS:|-AVC-[01]:)' guest-lines.log
